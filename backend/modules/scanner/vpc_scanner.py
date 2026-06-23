import boto3
from botocore.exceptions import ClientError


def scan_vpc(session: boto3.Session, region: str) -> list[dict]:
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
    except ClientError:
        return findings

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]

        # Default VPC check
        if vpc.get("IsDefault"):
            try:
                reservations = ec2.describe_instances(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "instance-state-name", "Values": ["running"]},
                    ]
                )["Reservations"]
                if reservations:
                    count = sum(len(r["Instances"]) for r in reservations)
                    findings.append(_finding(
                        "Medium",
                        f"VPC {vpc_id}: Default VPC has {count} running EC2 instance(s)",
                        "Running workloads in the default VPC is a security anti-pattern. Default VPCs have permissive configurations that can expose resources.",
                        "Create a custom VPC with private subnets and migrate your instances to it.",
                        "VPC", vpc_id, region,
                    ))
            except ClientError:
                pass

        # VPC Flow Logs
        try:
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            if not flow_logs:
                findings.append(_finding(
                    "Medium",
                    f"VPC {vpc_id}: Flow Logs not enabled",
                    "Without VPC Flow Logs, there is no record of network traffic. You cannot detect port scanning, data exfiltration, or lateral movement.",
                    "Enable VPC Flow Logs and send them to CloudWatch Logs or S3 for analysis.",
                    "VPC", vpc_id, region,
                ))
        except ClientError:
            pass

        # Default security group — should restrict all traffic
        try:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )["SecurityGroups"]
            for sg in sgs:
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    findings.append(_finding(
                        "Medium",
                        f"VPC {vpc_id}: Default security group allows traffic",
                        "CIS Benchmark requires the default security group to restrict all inbound and outbound traffic. Resources should not use the default SG.",
                        "Remove all rules from the default security group and ensure no resources use it.",
                        "VPC", sg["GroupId"], region,
                    ))
        except ClientError:
            pass

    return findings


def _finding(severity, title, description, remediation, service, resource_id, region) -> dict:
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "service": service,
        "resource_id": resource_id,
        "region": region,
        "module": "misconfig",
    }
