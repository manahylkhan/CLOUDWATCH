import json
import boto3
from botocore.exceptions import ClientError

_PRIV_ESC_ACTIONS = {"iam:*", "sts:*", "organizations:*"}
_SENSITIVE_PREFIXES = ("iam:", "sts:", "s3:Delete", "ec2:Terminate", "rds:Delete", "lambda:Delete")


def analyze_all_policies(session: boto3.Session) -> list[dict]:
    iam = session.client("iam")
    findings = []

    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )["PolicyVersion"]["Document"]
                    policy_findings = analyze_policy_document(version)
                    for pf in policy_findings:
                        pf["title"] = f"Policy {policy['PolicyName']}: {pf['issue']}"
                        pf["resource_id"] = policy["PolicyName"]
                        pf["resource_arn"] = policy["Arn"]
                        pf.pop("issue", None)
                        findings.append(pf)
                except ClientError:
                    pass
    except ClientError:
        pass

    # Check inline policies on users
    try:
        users = iam.list_users()["Users"]
        for user in users:
            uname = user["UserName"]
            try:
                inline_names = iam.list_user_policies(UserName=uname).get("PolicyNames", [])
                for policy_name in inline_names:
                    doc = iam.get_user_policy(UserName=uname, PolicyName=policy_name)["PolicyDocument"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    pf_list = analyze_policy_document(doc)
                    for pf in pf_list:
                        pf["title"] = f"Inline policy {policy_name} on user {uname}: {pf['issue']}"
                        pf["resource_id"] = uname
                        pf.pop("issue", None)
                        findings.append(pf)
                    if inline_names:
                        findings.append({
                            "severity": "Low",
                            "title": f"IAM User {uname}: Has inline policy '{policy_name}' (use managed policies instead)",
                            "description": "Inline policies are harder to audit and manage than managed policies.",
                            "remediation": "Convert inline policies to managed policies.",
                            "service": "IAM", "resource_id": uname, "region": "global", "module": "iam",
                        })
            except ClientError:
                pass
    except ClientError:
        pass

    return findings


def analyze_policy_document(policy_doc: dict) -> list[dict]:
    findings = []
    for statement in policy_doc.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions:
            findings.append({
                "severity": "Critical",
                "issue": "Wildcard action (*) allows ALL AWS actions",
                "description": "This policy allows every possible AWS action. Any principal with this policy has full AWS access.",
                "remediation": "Replace * with only the specific actions required.",
                "service": "IAM", "region": "global", "module": "iam",
            })

        for action in actions:
            if action in _PRIV_ESC_ACTIONS or action == "iam:*" or action == "sts:*":
                findings.append({
                    "severity": "Critical",
                    "issue": f"{action} allows privilege escalation",
                    "description": f"The action {action} can be used to escalate privileges — create users, attach policies, or assume any role.",
                    "remediation": f"Remove {action} and grant only the specific actions needed.",
                    "service": "IAM", "region": "global", "module": "iam",
                })

        if "*" in resources:
            sensitive = [a for a in actions if any(a.startswith(p) for p in _SENSITIVE_PREFIXES)]
            if sensitive:
                findings.append({
                    "severity": "High",
                    "issue": f"Sensitive actions {sensitive} allowed on all resources (*)",
                    "description": "Sensitive destructive/privilege actions are allowed on every resource in the account.",
                    "remediation": "Scope resource ARNs to specific resources instead of using *.",
                    "service": "IAM", "region": "global", "module": "iam",
                })

    return findings
