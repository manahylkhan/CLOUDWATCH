import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def create_session(access_key: str, secret_key: str, region: str = "us-east-1") -> boto3.Session:
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )
    try:
        sts = session.client("sts")
        sts.get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        raise ValueError(f"Invalid AWS credentials: {e}")
    return session


def get_account_id(session: boto3.Session) -> str:
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def list_enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return [r["RegionName"] for r in response["Regions"]]
