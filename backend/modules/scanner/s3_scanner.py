import boto3
from botocore.exceptions import ClientError


def scan_s3(session: boto3.Session) -> list[dict]:
    s3 = session.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError:
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        except ClientError:
            loc = "us-east-1"

        # Check 1: Public Access Block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([
                pab.get("BlockPublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("IgnorePublicAcls"),
                pab.get("RestrictPublicBuckets"),
            ]):
                findings.append(_finding(
                    severity="Critical",
                    title=f"S3 Bucket {name}: Public Access not fully blocked",
                    description="One or more Block Public Access settings are disabled, allowing potential public exposure.",
                    remediation="Enable all 4 Block Public Access settings on the bucket: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets.",
                    service="S3", resource_id=name, region=loc,
                ))
        except ClientError as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                findings.append(_finding(
                    severity="Critical",
                    title=f"S3 Bucket {name}: No Public Access Block configured",
                    description="Block Public Access has never been configured on this bucket — it may be publicly accessible.",
                    remediation="Enable all 4 Block Public Access settings in S3 console or via CLI.",
                    service="S3", resource_id=name, region=loc,
                ))

        # Check 2: Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            findings.append(_finding(
                severity="High",
                title=f"S3 Bucket {name}: No default encryption configured",
                description="Objects uploaded to this bucket are not encrypted at rest by default.",
                remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                service="S3", resource_id=name, region=loc,
            ))

        # Check 3: Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append(_finding(
                    severity="Medium",
                    title=f"S3 Bucket {name}: Versioning not enabled",
                    description="Versioning protects against accidental deletion and ransomware. It is currently disabled.",
                    remediation="Enable versioning on the S3 bucket.",
                    service="S3", resource_id=name, region=loc,
                ))
        except ClientError:
            pass

        # Check 4: Access Logging
        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                findings.append(_finding(
                    severity="Low",
                    title=f"S3 Bucket {name}: Access logging not enabled",
                    description="Without access logging, there is no record of who accessed or downloaded objects.",
                    remediation="Enable S3 server access logging and point it to a dedicated log bucket.",
                    service="S3", resource_id=name, region=loc,
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
