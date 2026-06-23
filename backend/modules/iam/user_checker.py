import csv
import io
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


def check_iam_users(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    findings = []

    try:
        iam.generate_credential_report()
        time.sleep(3)
        report_text = iam.get_credential_report()["Content"].decode("utf-8")
    except ClientError:
        return findings

    reader = csv.DictReader(io.StringIO(report_text))
    for row in reader:
        user = row["user"]
        if user == "<root_account>":
            continue

        # MFA check for console users
        if row.get("mfa_active") == "false" and row.get("password_enabled") == "true":
            findings.append(_f(
                "High",
                f"IAM User {user}: MFA not enabled",
                f"User {user} has console (password) access but no MFA enabled. A stolen password gives full account access.",
                f"Enable MFA for user {user} in IAM console.",
                user,
            ))

        # Access key age
        for key_num in ("1", "2"):
            active = row.get(f"access_key_{key_num}_active") == "true"
            rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
            last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")

            if active and rotated not in ("N/A", "n/a", ""):
                try:
                    last_dt = datetime.fromisoformat(rotated.replace("Z", "+00:00"))
                    days_old = (datetime.now(timezone.utc) - last_dt).days
                    if days_old > 90:
                        findings.append(_f(
                            "Medium",
                            f"IAM User {user}: Access key {key_num} is {days_old} days old",
                            f"Access key {key_num} for user {user} has not been rotated in {days_old} days. CIS requires rotation every 90 days.",
                            f"Rotate access key {key_num} for user {user}. Create a new key, update applications, then delete the old one.",
                            user,
                        ))
                except ValueError:
                    pass

            if active and last_used in ("N/A", "n/a", ""):
                findings.append(_f(
                    "Medium",
                    f"IAM User {user}: Access key {key_num} has never been used",
                    f"Active access key {key_num} for {user} has never been used. Unused credentials increase the attack surface.",
                    f"Delete unused access key {key_num} for user {user}.",
                    user,
                ))

        # Check for inactive console users
        last_login = row.get("password_last_used", "N/A")
        has_password = row.get("password_enabled") == "true"
        if has_password and last_login not in ("N/A", "no_information", "not_supported", ""):
            try:
                last_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                days_ago = (datetime.now(timezone.utc) - last_dt).days
                if days_ago > 90:
                    findings.append(_f(
                        "Low",
                        f"IAM User {user}: No console login in {days_ago} days",
                        f"User {user} has not logged into the console in {days_ago} days. Inactive accounts should be reviewed.",
                        f"Disable or remove user {user} if they no longer need AWS access.",
                        user,
                    ))
            except ValueError:
                pass

    return findings


def check_admin_users(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    findings = []
    try:
        users = iam.list_users()["Users"]
        for user in users:
            uname = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
            for p in attached:
                if "AdministratorAccess" in p["PolicyName"]:
                    findings.append(_f(
                        "High",
                        f"IAM User {uname}: AdministratorAccess policy directly attached",
                        f"User {uname} has AdministratorAccess attached directly — not via a group. Direct policy attachments are hard to audit and manage.",
                        "Remove the direct policy attachment. Add the user to an admin IAM group and attach the policy to the group instead.",
                        uname,
                    ))
    except ClientError:
        pass
    return findings


def _f(severity, title, description, remediation, user) -> dict:
    return {
        "severity": severity, "title": title, "description": description,
        "remediation": remediation, "service": "IAM", "resource_id": user,
        "region": "global", "module": "iam",
    }
