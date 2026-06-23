import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Text, DateTime,
    ForeignKey, Enum as SAEnum
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def new_uuid() -> str:
    return str(uuid.uuid4())


class AWSAccount(Base):
    __tablename__ = "aws_accounts"

    id = Column(String, primary_key=True, default=new_uuid)
    account_alias = Column(String, nullable=False)
    account_id = Column(String, nullable=True)
    access_key_encrypted = Column(Text, nullable=False)
    secret_key_encrypted = Column(Text, nullable=False)
    default_region = Column(String, default="us-east-1")
    scan_all_regions = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scan_at = Column(DateTime, nullable=True)

    scans = relationship("Scan", back_populates="account", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=new_uuid)
    account_id = Column(String, ForeignKey("aws_accounts.id"), nullable=False)
    status = Column(SAEnum("running", "completed", "failed", name="scan_status"), default="running")
    modules_run = Column(String, default="")
    security_score = Column(Integer, nullable=True)
    grade = Column(String, nullable=True)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    ai_summary = Column(Text, nullable=True)
    ai_roadmap = Column(Text, nullable=True)
    ai_chains = Column(Text, nullable=True)
    progress = Column(Integer, default=0)
    current_task = Column(String, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    # CIS Benchmark
    cis_results = Column(Text, nullable=True)   # JSON list of check results
    cis_score = Column(Integer, nullable=True)   # overall CIS compliance %
    # CloudTrail analysis
    cloudtrail_summary = Column(Text, nullable=True)
    cloudtrail_severity = Column(String, nullable=True)
    cloudtrail_assessment = Column(Text, nullable=True)
    cloudtrail_actions = Column(Text, nullable=True)  # JSON list
    cloudtrail_rule_findings = Column(Text, nullable=True)  # JSON list

    account = relationship("AWSAccount", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=new_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    module = Column(
        SAEnum("misconfig", "iam", "cloudtrail", "cis", name="finding_module"),
        nullable=False,
    )
    service = Column(String, nullable=False)
    resource_id = Column(String, nullable=True)
    resource_arn = Column(String, nullable=True)
    region = Column(String, default="global")
    severity = Column(
        SAEnum("Critical", "High", "Medium", "Low", "Info", name="finding_severity"),
        nullable=False,
    )
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    remediation_effort = Column(
        SAEnum("Easy", "Medium", "Complex", name="finding_effort"),
        nullable=True,
    )
    cis_check_id = Column(String, nullable=True)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "ai_explanation": self.ai_explanation,
            "remediation": self.remediation,
            "remediation_effort": self.remediation_effort,
            "cis_check_id": self.cis_check_id,
            "is_false_positive": self.is_false_positive,
        }
