"""CIS AWS Foundations Benchmark v2.0 — automated checks."""
import csv
import io
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def _check(cis_id: str, title: str, status: str, evidence: str, remediation: str, section: str) -> dict:
    return {
        "cis_id": cis_id,
        "title": title,
        "status": status,  # Pass | Fail | NA
        "evidence": evidence,
        "remediation": remediation,
        "section": section,
    }


def run_cis_checks(session: boto3.Session, regions: list[str]) -> list[dict]:
    results: list[dict] = []
    iam = session.client("iam")
    ec2_global = session.client("ec2", region_name="us-east-1")

    # ─── Section 1: IAM ──────────────────────────────────────────────────────
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa = summary.get("AccountMFAEnabled", 0)
        results.append(_check("1.1", "Root MFA enabled",
            "Pass" if mfa else "Fail",
            f"AccountMFAEnabled={mfa}",
            "Enable MFA on the root account via AWS Console > Security Credentials.",
            "iam"))

        keys = summary.get("AccountAccessKeysPresent", 0)
        results.append(_check("1.2", "No root account access keys",
            "Pass" if keys == 0 else "Fail",
            f"AccountAccessKeysPresent={keys}",
            "Delete all root account access keys immediately.",
            "iam"))
    except ClientError:
        pass

    # Credential report checks
    try:
        iam.generate_credential_report()
        time.sleep(3)
        report_text = iam.get_credential_report()["Content"].decode("utf-8")
        reader = list(csv.DictReader(io.StringIO(report_text)))

        # 1.3 MFA on all console users
        no_mfa = [r["user"] for r in reader
                  if r["user"] != "<root_account>"
                  and r.get("password_enabled") == "true"
                  and r.get("mfa_active") == "false"]
        results.append(_check("1.3", "MFA enabled for all IAM users with console access",
            "Pass" if not no_mfa else "Fail",
            f"Users without MFA: {no_mfa[:5]}{'...' if len(no_mfa)>5 else ''}",
            "Enable MFA for every IAM user with console access.",
            "iam"))

        # 1.4 Access keys rotated < 90 days
        old_keys = []
        for row in reader:
            if row["user"] == "<root_account>":
                continue
            for n in ("1", "2"):
                if row.get(f"access_key_{n}_active") == "true":
                    rotated = row.get(f"access_key_{n}_last_rotated", "N/A")
                    if rotated not in ("N/A", "n/a", ""):
                        try:
                            dt = datetime.fromisoformat(rotated.replace("Z", "+00:00"))
                            if (datetime.now(timezone.utc) - dt).days > 90:
                                old_keys.append(row["user"])
                        except ValueError:
                            pass
        results.append(_check("1.4", "Access keys rotated within 90 days",
            "Pass" if not old_keys else "Fail",
            f"Users with old keys: {old_keys[:5]}",
            "Rotate access keys older than 90 days.",
            "iam"))
    except ClientError:
        pass

    # 1.5–1.11 Password policy
    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
        results.append(_check("1.5", "Password minimum length >= 14",
            "Pass" if pp.get("MinimumPasswordLength", 0) >= 14 else "Fail",
            f"MinLength={pp.get('MinimumPasswordLength',0)}",
            "Set minimum password length to 14.", "iam"))
        results.append(_check("1.6", "Password requires uppercase",
            "Pass" if pp.get("RequireUppercaseCharacters") else "Fail",
            f"RequireUppercase={pp.get('RequireUppercaseCharacters')}",
            "Enable uppercase requirement.", "iam"))
        results.append(_check("1.7", "Password requires lowercase",
            "Pass" if pp.get("RequireLowercaseCharacters") else "Fail",
            f"RequireLowercase={pp.get('RequireLowercaseCharacters')}",
            "Enable lowercase requirement.", "iam"))
        results.append(_check("1.8", "Password requires numbers",
            "Pass" if pp.get("RequireNumbers") else "Fail",
            f"RequireNumbers={pp.get('RequireNumbers')}",
            "Enable numbers requirement.", "iam"))
        results.append(_check("1.9", "Password requires symbols",
            "Pass" if pp.get("RequireSymbols") else "Fail",
            f"RequireSymbols={pp.get('RequireSymbols')}",
            "Enable symbols requirement.", "iam"))
        max_age = pp.get("MaxPasswordAge", 0)
        results.append(_check("1.10", "Password expiry <= 90 days",
            "Pass" if max_age and max_age <= 90 else "Fail",
            f"MaxPasswordAge={max_age}",
            "Set password expiry to 90 days or less.", "iam"))
        reuse = pp.get("PasswordReusePrevention", 0)
        results.append(_check("1.11", "Password reuse prevention >= 24",
            "Pass" if reuse >= 24 else "Fail",
            f"PasswordReusePrevention={reuse}",
            "Set password reuse prevention to 24.", "iam"))
    except ClientError:
        results.append(_check("1.5", "Password minimum length >= 14", "Fail",
            "No password policy configured",
            "Create an IAM password policy.", "iam"))

    # ─── Section 2: Storage ──────────────────────────────────────────────────
    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])

        # 2.1 S3 account-level block public access
        try:
            s3_control = session.client("s3control", region_name="us-east-1")
            account_id = session.client("sts").get_caller_identity()["Account"]
            pab = s3_control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
            all_blocked = all([pab.get("BlockPublicAcls"), pab.get("BlockPublicPolicy"),
                               pab.get("IgnorePublicAcls"), pab.get("RestrictPublicBuckets")])
            results.append(_check("2.1", "S3 account-level Block Public Access enabled",
                "Pass" if all_blocked else "Fail",
                f"BlockPublicAcls={pab.get('BlockPublicAcls')}, BlockPublicPolicy={pab.get('BlockPublicPolicy')}",
                "Enable all 4 Block Public Access settings at the account level in S3 console.",
                "storage"))
        except ClientError:
            results.append(_check("2.1", "S3 account-level Block Public Access enabled",
                "Fail", "Unable to read account-level S3 public access block",
                "Enable Block Public Access at the S3 account level.", "storage"))

        # 2.3 Logging on all buckets
        no_log = [b["Name"] for b in buckets if _no_logging(s3, b["Name"])]
        results.append(_check("2.3", "S3 access logging enabled on all buckets",
            "Pass" if not no_log else "Fail",
            f"Buckets without logging: {no_log[:5]}",
            "Enable S3 access logging on all buckets.", "storage"))

        # 2.4 No public buckets
        public_buckets = [b["Name"] for b in buckets if _is_public(s3, b["Name"])]
        results.append(_check("2.4", "No S3 buckets publicly accessible",
            "Pass" if not public_buckets else "Fail",
            f"Public buckets: {public_buckets[:5]}",
            "Enable Block Public Access on all public buckets.", "storage"))
    except ClientError:
        pass

    # ─── Section 3: Logging ──────────────────────────────────────────────────
    try:
        ct = session.client("cloudtrail", region_name="us-east-1")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        results.append(_check("3.1", "CloudTrail enabled in all regions (multi-region trail)",
            "Pass" if multi_region else "Fail",
            f"Multi-region trails: {len(multi_region)}",
            "Create a multi-region CloudTrail trail.", "logging"))

        validated = [t for t in trails if t.get("LogFileValidationEnabled")]
        results.append(_check("3.2", "CloudTrail log file validation enabled",
            "Pass" if validated else "Fail",
            f"Trails with validation: {len(validated)} of {len(trails)}",
            "Enable log file validation on all CloudTrail trails.", "logging"))

        encrypted = [t for t in trails if t.get("KMSKeyId")]
        results.append(_check("3.4", "CloudTrail logs encrypted with KMS",
            "Pass" if encrypted else "Fail",
            f"Trails with KMS: {len(encrypted)} of {len(trails)}",
            "Enable KMS encryption on CloudTrail trails.", "logging"))

        cw_integrated = [t for t in trails if t.get("CloudWatchLogsLogGroupArn")]
        results.append(_check("3.5", "CloudTrail integrated with CloudWatch Logs",
            "Pass" if cw_integrated else "Fail",
            f"Trails with CW Logs: {len(cw_integrated)} of {len(trails)}",
            "Configure CloudTrail to send logs to CloudWatch Logs.", "logging"))
    except ClientError:
        pass

    # 3.3 AWS Config enabled
    try:
        config = session.client("config", region_name=regions[0] if regions else "us-east-1")
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        recording = any(s.get("recording") for s in statuses)
        results.append(_check("3.3", "AWS Config enabled",
            "Pass" if recorders and recording else "Fail",
            f"Recorders={len(recorders)}, recording={recording}",
            "Enable AWS Config in all regions.", "logging"))
    except ClientError:
        results.append(_check("3.3", "AWS Config enabled", "Fail",
            "Unable to check Config status", "Enable AWS Config.", "logging"))

    # ─── Section 4: Monitoring (CloudWatch Alarms) ───────────────────────────
    cw_checks = [
        ("4.1", "Alarm for unauthorized API calls", "UnauthorizedAPICalls"),
        ("4.2", "Alarm for console sign-in without MFA", "ConsoleSigninWithoutMFA"),
        ("4.3", "Alarm for root account usage", "RootAccountUsage"),
        ("4.4", "Alarm for IAM policy changes", "IAMPolicyChanges"),
        ("4.5", "Alarm for CloudTrail config changes", "CloudTrailChanges"),
        ("4.6", "Alarm for console authentication failures", "ConsoleAuthFailures"),
    ]
    try:
        cw = session.client("cloudwatch", region_name=regions[0] if regions else "us-east-1")
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        alarm_names = [a["AlarmName"].lower() for a in alarms]
        for cis_id, title, keyword in cw_checks:
            found = any(keyword.lower() in n for n in alarm_names)
            results.append(_check(cis_id, title,
                "Pass" if found else "Fail",
                f"Alarm matching '{keyword}': {'found' if found else 'not found'}",
                f"Create a CloudWatch alarm for {keyword} events via CloudTrail metric filter.",
                "monitoring"))
    except ClientError:
        for cis_id, title, _ in cw_checks:
            results.append(_check(cis_id, title, "Fail",
                "Unable to check CloudWatch alarms", "Create required CloudWatch alarms.", "monitoring"))

    # ─── Section 5: Networking ───────────────────────────────────────────────
    ssh_exposed = []
    rdp_exposed = []
    default_sg_traffic = []
    no_flow_logs = []

    for region in regions[:5]:  # check up to 5 regions
        try:
            ec2 = session.client("ec2", region_name=region)
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    fp = rule.get("FromPort", 0)
                    for ipr in rule.get("IpRanges", []):
                        if ipr.get("CidrIp") == "0.0.0.0/0":
                            if fp == 22:
                                ssh_exposed.append(sg["GroupId"])
                            if fp == 3389:
                                rdp_exposed.append(sg["GroupId"])
                if sg.get("GroupName") == "default":
                    if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                        default_sg_traffic.append(sg["GroupId"])

            vpcs = ec2.describe_vpcs()["Vpcs"]
            for vpc in vpcs:
                fl = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc["VpcId"]]}]
                )["FlowLogs"]
                if not fl:
                    no_flow_logs.append(vpc["VpcId"])
        except ClientError:
            pass

    results.append(_check("5.1", "No security groups allow 0.0.0.0/0 to port 22 (SSH)",
        "Pass" if not ssh_exposed else "Fail",
        f"SGs with SSH open: {ssh_exposed[:5]}",
        "Restrict SSH access to specific IP ranges.", "networking"))
    results.append(_check("5.2", "No security groups allow 0.0.0.0/0 to port 3389 (RDP)",
        "Pass" if not rdp_exposed else "Fail",
        f"SGs with RDP open: {rdp_exposed[:5]}",
        "Restrict RDP access to specific IP ranges.", "networking"))
    results.append(_check("5.3", "Default security group restricts all traffic",
        "Pass" if not default_sg_traffic else "Fail",
        f"Default SGs with rules: {default_sg_traffic[:5]}",
        "Remove all rules from default security groups.", "networking"))
    results.append(_check("5.4", "VPC Flow Logging enabled in all VPCs",
        "Pass" if not no_flow_logs else "Fail",
        f"VPCs without flow logs: {no_flow_logs[:5]}",
        "Enable VPC Flow Logs for all VPCs.", "networking"))

    return results


def calculate_cis_score(results: list[dict]) -> dict:
    passed = [r for r in results if r["status"] == "Pass"]
    failed = [r for r in results if r["status"] == "Fail"]
    total = len(passed) + len(failed)
    overall = round(len(passed) / total * 100) if total > 0 else 0

    sections = ["iam", "storage", "logging", "monitoring", "networking"]
    by_section = {}
    for sec in sections:
        sec_results = [r for r in results if r["section"] == sec]
        sec_passed = sum(1 for r in sec_results if r["status"] == "Pass")
        by_section[sec] = {
            "passed": sec_passed,
            "total": len(sec_results),
            "percent": round(sec_passed / len(sec_results) * 100) if sec_results else 0,
        }

    return {
        "overall_percent": overall,
        "passed": len(passed),
        "failed": len(failed),
        "total": total,
        "by_section": by_section,
    }


def cis_results_to_findings(results: list[dict], scan_id: str) -> list[dict]:
    findings = []
    for r in results:
        if r["status"] != "Fail":
            continue
        findings.append({
            "severity": _cis_severity(r["cis_id"]),
            "title": f"CIS {r['cis_id']}: {r['title']}",
            "description": r["evidence"],
            "remediation": r["remediation"],
            "service": "CIS",
            "resource_id": r["cis_id"],
            "region": "global",
            "module": "cis",
            "cis_check_id": r["cis_id"],
        })
    return findings


def _cis_severity(cis_id: str) -> str:
    critical = {"1.1", "1.2", "1.3", "1.12", "2.4", "3.1", "5.1", "5.2"}
    high = {"1.4", "1.5", "2.1", "3.2", "3.4", "3.5", "4.3", "5.3", "5.4"}
    if cis_id in critical:
        return "Critical"
    if cis_id in high:
        return "High"
    return "Medium"


def _no_logging(s3, bucket_name: str) -> bool:
    try:
        cfg = s3.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" not in cfg
    except ClientError:
        return False


def _is_public(s3, bucket_name: str) -> bool:
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        return not all([pab.get("BlockPublicAcls"), pab.get("BlockPublicPolicy"),
                        pab.get("IgnorePublicAcls"), pab.get("RestrictPublicBuckets")])
    except ClientError:
        return True
