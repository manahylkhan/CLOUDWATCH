import boto3
from .root_checker import check_root_account
from .user_checker import check_iam_users, check_admin_users
from .policy_analyzer import analyze_all_policies
from .password_policy import check_password_policy


def run_iam_scan(session: boto3.Session) -> list[dict]:
    findings: list[dict] = []

    for fn in (check_root_account, check_iam_users, check_admin_users,
               analyze_all_policies, check_password_policy):
        try:
            findings.extend(fn(session))
        except Exception:
            pass

    return findings
