import boto3
from botocore.exceptions import ClientError


def check_password_policy(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    findings = []

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if "NoSuchEntity" in str(e):
            findings.append(_f(
                "High",
                "No IAM password policy configured",
                "There is no account-level password policy. Users can set any password, including weak ones.",
                "Create an IAM password policy that meets CIS requirements: min length 14, complexity required, expiry 90 days.",
            ))
        return findings

    if policy.get("MinimumPasswordLength", 0) < 14:
        findings.append(_f(
            "Medium",
            f"Password policy: Minimum length is {policy.get('MinimumPasswordLength', 0)} (should be ≥ 14)",
            "Short passwords are easier to brute-force. CIS requires a minimum of 14 characters.",
            "Update the password policy to require at least 14 characters.",
        ))

    if not policy.get("RequireUppercaseCharacters"):
        findings.append(_f("Low", "Password policy: Uppercase letters not required", "Passwords without uppercase are less complex.", "Enable uppercase requirement in IAM password policy."))

    if not policy.get("RequireLowercaseCharacters"):
        findings.append(_f("Low", "Password policy: Lowercase letters not required", "Passwords without lowercase are less complex.", "Enable lowercase requirement in IAM password policy."))

    if not policy.get("RequireNumbers"):
        findings.append(_f("Low", "Password policy: Numbers not required", "Passwords without numbers are less complex.", "Enable numbers requirement in IAM password policy."))

    if not policy.get("RequireSymbols"):
        findings.append(_f("Low", "Password policy: Symbols not required", "Passwords without symbols are less complex.", "Enable symbols requirement in IAM password policy."))

    max_age = policy.get("MaxPasswordAge")
    if not max_age or max_age > 90:
        findings.append(_f(
            "Medium",
            f"Password policy: Password expiry is {'not set' if not max_age else f'{max_age} days (> 90)'}",
            "Passwords that never expire remain valid even after a breach.",
            "Set password expiry to 90 days or less in IAM password policy.",
        ))

    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse < 24:
        findings.append(_f(
            "Low",
            f"Password policy: Only prevents reuse of last {reuse} passwords (should be ≥ 24)",
            "Users can cycle through old passwords to reuse compromised credentials.",
            "Set password reuse prevention to at least 24 in IAM password policy.",
        ))

    return findings


def _f(severity, title, description, remediation) -> dict:
    return {
        "severity": severity, "title": title, "description": description,
        "remediation": remediation, "service": "IAM", "resource_id": "password-policy",
        "region": "global", "module": "iam",
    }
