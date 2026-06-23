import csv
import io
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def check_root_account(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    findings = []

    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError:
        return findings

    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append(_f(
            "Critical",
            "Root account: MFA not enabled",
            "The AWS root account has no MFA device. Anyone who obtains the root password can access everything in your AWS account with no second factor check.",
            "Enable MFA on the root account immediately. Use a hardware MFA device if possible. Go to AWS Console > Security Credentials.",
        ))

    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(_f(
            "Critical",
            "Root account: Active access keys exist",
            "The root account has programmatic access keys. These keys grant unrestricted access to your entire AWS account and should never exist.",
            "Delete all root account access keys immediately. Use IAM users with appropriate permissions for programmatic access.",
        ))

    try:
        iam.generate_credential_report()
        time.sleep(3)
        report_bytes = iam.get_credential_report()["Content"]
        report_text = report_bytes.decode("utf-8")
        reader = csv.DictReader(io.StringIO(report_text))
        for row in reader:
            if row["user"] == "<root_account>":
                last_used = row.get("password_last_used", "N/A")
                if last_used not in ("N/A", "no_information", "not_supported", ""):
                    try:
                        last_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                        days_ago = (datetime.now(timezone.utc) - last_dt).days
                        if days_ago < 90:
                            findings.append(_f(
                                "High",
                                f"Root account: Used {days_ago} day(s) ago",
                                f"The root account was used {days_ago} days ago. Root should only be used for initial setup and rare account-level tasks.",
                                "Stop using the root account for daily operations. Create an IAM admin user instead and use that.",
                            ))
                    except ValueError:
                        pass
    except ClientError:
        pass

    return findings


def _f(severity, title, description, remediation) -> dict:
    return {
        "severity": severity, "title": title, "description": description,
        "remediation": remediation, "service": "IAM", "resource_id": "root",
        "region": "global", "module": "iam",
    }
