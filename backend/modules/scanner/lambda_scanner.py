import re
import boto3
from botocore.exceptions import ClientError

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api_?key|apikey|secret|password|passwd|token|credential)\s*[=:]?\s*.{4,}"),
    re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]?\s*.{4,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
]


def scan_lambda(session: boto3.Session, region: str) -> list[dict]:
    lmb = session.client("lambda", region_name=region)
    findings = []

    try:
        paginator = lmb.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page["Functions"])
    except ClientError:
        return findings

    for fn in functions:
        fn_name = fn["FunctionName"]
        fn_arn = fn.get("FunctionArn", "")

        # Check env vars for secrets
        env_vars = fn.get("Environment", {}).get("Variables", {})
        for key, value in env_vars.items():
            candidate = f"{key}={value}"
            for pattern in _SECRET_PATTERNS:
                if pattern.search(candidate):
                    findings.append(_finding(
                        "High",
                        f"Lambda {fn_name}: Potential secret in environment variable '{key}'",
                        f"The environment variable '{key}' appears to contain a secret, API key, or credential. Storing secrets in plain text env vars is dangerous.",
                        "Use AWS Secrets Manager or SSM Parameter Store (SecureString) to store secrets. Reference them at runtime.",
                        "Lambda", fn_name, region, fn_arn,
                    ))
                    break

        # Check execution role for over-privilege
        role_arn = fn.get("Role", "")
        if role_arn:
            try:
                iam = session.client("iam")
                role_name = role_arn.split("/")[-1]
                policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                for policy in policies:
                    if policy["PolicyName"] == "AdministratorAccess":
                        findings.append(_finding(
                            "Critical",
                            f"Lambda {fn_name}: Execution role has AdministratorAccess",
                            "The Lambda function's IAM role has full AWS AdministratorAccess. If this function is compromised, an attacker gains full AWS account access.",
                            "Apply least privilege — grant only the specific IAM actions the function needs.",
                            "Lambda", fn_name, region, fn_arn,
                        ))
            except ClientError:
                pass

        # Check for public function URL without auth
        try:
            url_config = lmb.get_function_url_config(FunctionName=fn_name)
            if url_config.get("AuthType") == "NONE":
                findings.append(_finding(
                    "High",
                    f"Lambda {fn_name}: Public function URL with no authentication",
                    "This Lambda function is publicly accessible via a URL with no authentication required.",
                    "Set AuthType to AWS_IAM, or remove the function URL if not needed.",
                    "Lambda", fn_name, region, fn_arn,
                ))
        except ClientError:
            pass

    return findings


def _finding(severity, title, description, remediation, service, resource_id, region, arn=None) -> dict:
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "service": service,
        "resource_id": resource_id,
        "resource_arn": arn,
        "region": region,
        "module": "misconfig",
    }
