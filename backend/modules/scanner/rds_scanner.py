import boto3
from botocore.exceptions import ClientError


def scan_rds(session: boto3.Session, region: str) -> list[dict]:
    rds = session.client("rds", region_name=region)
    findings = []

    try:
        instances = rds.describe_db_instances()["DBInstances"]
    except ClientError:
        return findings

    for db in instances:
        db_id = db["DBInstanceIdentifier"]
        engine = db.get("Engine", "")

        if db.get("PubliclyAccessible"):
            findings.append(_finding(
                "Critical",
                f"RDS {db_id}: Publicly accessible from internet",
                f"The {engine} database {db_id} is configured to allow connections from the public internet.",
                "Set PubliclyAccessible to false. Place the RDS instance inside a private subnet with no internet gateway route.",
                "RDS", db_id, region,
            ))

        if not db.get("StorageEncrypted"):
            findings.append(_finding(
                "High",
                f"RDS {db_id}: Storage not encrypted at rest",
                "Database storage is not encrypted. Data-at-rest is exposed if the underlying storage is compromised.",
                "Enable storage encryption. Note: existing instances must be snapshotted and restored as encrypted.",
                "RDS", db_id, region,
            ))

        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(_finding(
                "Medium",
                f"RDS {db_id}: Automated backups disabled",
                "Without automated backups, data cannot be recovered after accidental deletion or corruption.",
                "Set backup retention period to at least 7 days in RDS console.",
                "RDS", db_id, region,
            ))

        db_class = db.get("DBInstanceClass", "")
        if not db.get("MultiAZ") and db_class.startswith("db.m"):
            findings.append(_finding(
                "Medium",
                f"RDS {db_id}: Multi-AZ not enabled (single point of failure)",
                "This production-class instance has no standby. A failure in one availability zone will cause downtime.",
                "Enable Multi-AZ deployment for production databases.",
                "RDS", db_id, region,
            ))

        if db.get("DBSubnetGroup", {}).get("VpcId") == "":
            findings.append(_finding(
                "Medium",
                f"RDS {db_id}: Appears to be in default VPC",
                "Using the default VPC for databases is a security anti-pattern.",
                "Migrate the RDS instance to a custom VPC with private subnets.",
                "RDS", db_id, region,
            ))

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
