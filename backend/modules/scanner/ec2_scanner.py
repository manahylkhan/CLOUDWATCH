import boto3
from botocore.exceptions import ClientError

_DB_PORTS = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}


def scan_security_groups(session: boto3.Session, region: str) -> list[dict]:
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError:
        return findings

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            open_to_internet = any(
                r.get("CidrIp") in ["0.0.0.0/0"] for r in rule.get("IpRanges", [])
            ) or any(
                r.get("CidrIpv6") in ["::/0"] for r in rule.get("Ipv6Ranges", [])
            )

            if not open_to_internet:
                continue

            if from_port == 22:
                findings.append(_finding(
                    "Critical",
                    f"Security Group {sg_name} ({sg_id}): SSH (22) open to internet",
                    "Port 22 (SSH) is exposed to the entire internet (0.0.0.0/0). An attacker can attempt to brute-force or exploit SSH.",
                    "Restrict SSH access to specific trusted IP ranges only.",
                    "EC2", sg_id, region,
                ))
            elif from_port == 3389:
                findings.append(_finding(
                    "Critical",
                    f"Security Group {sg_name} ({sg_id}): RDP (3389) open to internet",
                    "Port 3389 (RDP) is exposed to the entire internet. This is a top vector for ransomware attacks.",
                    "Restrict RDP access to a VPN or specific IPs. Never expose RDP to 0.0.0.0/0.",
                    "EC2", sg_id, region,
                ))
            elif from_port == 0 and to_port == 65535:
                findings.append(_finding(
                    "Critical",
                    f"Security Group {sg_name} ({sg_id}): ALL ports open to internet",
                    "All ports are open to the entire internet. This effectively removes all network security.",
                    "Remove the all-ports open rule. Allow only the specific ports your application needs.",
                    "EC2", sg_id, region,
                ))
            elif from_port in _DB_PORTS:
                db_name = _DB_PORTS[from_port]
                findings.append(_finding(
                    "Critical",
                    f"Security Group {sg_name} ({sg_id}): {db_name} port ({from_port}) open to internet",
                    f"{db_name} database port is exposed to the internet. Databases should never be publicly accessible.",
                    f"Remove public access to port {from_port}. Databases should only be accessible within the VPC.",
                    "EC2", sg_id, region,
                ))

    return findings


def scan_ec2_instances(session: boto3.Session, region: str) -> list[dict]:
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        reservations = ec2.describe_instances()["Reservations"]
    except ClientError:
        return findings

    for r in reservations:
        for inst in r["Instances"]:
            inst_id = inst["InstanceId"]
            state = inst.get("State", {}).get("Name", "")
            if state not in ("running", "stopped"):
                continue

            # IMDSv1 check
            metadata_options = inst.get("MetadataOptions", {})
            if metadata_options.get("HttpTokens") == "optional":
                findings.append(_finding(
                    "Medium",
                    f"EC2 {inst_id}: IMDSv1 enabled (SSRF risk)",
                    "Instance Metadata Service v1 is enabled, which is vulnerable to SSRF attacks that can expose IAM credentials.",
                    "Set HttpTokens to 'required' to enforce IMDSv2.",
                    "EC2", inst_id, region,
                ))

            # EBS encryption
            for bdm in inst.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs", {})
                if not ebs.get("DeleteOnTermination") is None:
                    pass
                vol_id = ebs.get("VolumeId")
                if vol_id:
                    try:
                        vols = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"]
                        for vol in vols:
                            if not vol.get("Encrypted"):
                                findings.append(_finding(
                                    "Medium",
                                    f"EC2 {inst_id}: EBS volume {vol_id} not encrypted",
                                    "EBS volume data is stored unencrypted at rest.",
                                    "Enable EBS encryption. For existing volumes, create an encrypted snapshot and replace the volume.",
                                    "EC2", inst_id, region,
                                ))
                                break
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
