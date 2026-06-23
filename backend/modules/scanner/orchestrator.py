import json
from datetime import datetime

import boto3
from sqlalchemy.orm import Session

from models import Scan, Finding, AWSAccount
from modules.scanner.s3_scanner import scan_s3
from modules.scanner.ec2_scanner import scan_security_groups, scan_ec2_instances
from modules.scanner.rds_scanner import scan_rds
from modules.scanner.lambda_scanner import scan_lambda
from modules.scanner.vpc_scanner import scan_vpc
from modules.iam.orchestrator import run_iam_scan
from modules.cis.checker import run_cis_checks, calculate_cis_score, cis_results_to_findings
from modules.ai.enricher import enrich_findings_batch, generate_scan_summary
from config import SEVERITY_DEDUCTIONS


def _update_scan(db: Session, scan_id: str, **kwargs):
    db.query(Scan).filter(Scan.id == scan_id).update(kwargs)
    db.commit()


def _save_findings(db: Session, scan_id: str, raw_findings: list[dict]):
    for f in raw_findings:
        obj = Finding(
            scan_id=scan_id,
            module=f.get("module", "misconfig"),
            service=f.get("service", "Unknown"),
            resource_id=f.get("resource_id"),
            resource_arn=f.get("resource_arn"),
            region=f.get("region", "global"),
            severity=f["severity"],
            title=f["title"],
            description=f.get("description"),
            ai_explanation=f.get("ai_explanation"),
            remediation=f.get("remediation"),
            remediation_effort=f.get("remediation_effort"),
            cis_check_id=f.get("cis_check_id"),
        )
        db.add(obj)
    db.commit()


def _calculate_score(findings: list[dict]) -> tuple[int, str]:
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTIONS.get(f["severity"], 0)
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade


def run_full_scan(scan_id: str, db: Session, aws_session: boto3.Session,
                  regions: list[str], modules: list[str]):
    all_findings: list[dict] = []
    progress = 5

    # ── Misconfiguration Scanner ─────────────────────────────────────────────
    if "misconfig" in modules:
        _update_scan(db, scan_id, current_task="Scanning S3 buckets...", progress=progress)
        try:
            all_findings.extend(scan_s3(aws_session))
        except Exception:
            pass

        region_count = len(regions)
        for i, region in enumerate(regions):
            progress = 10 + int((i / max(region_count, 1)) * 30)
            _update_scan(db, scan_id, current_task=f"Scanning {region} (EC2/RDS/Lambda/VPC)...", progress=progress)
            for scanner in (scan_security_groups, scan_ec2_instances, scan_rds, scan_lambda, scan_vpc):
                try:
                    all_findings.extend(scanner(aws_session, region))
                except Exception:
                    pass

    # ── IAM Auditor ──────────────────────────────────────────────────────────
    if "iam" in modules:
        _update_scan(db, scan_id, current_task="Running IAM audit...", progress=42)
        try:
            all_findings.extend(run_iam_scan(aws_session))
        except Exception:
            pass

    # ── CIS Benchmark ────────────────────────────────────────────────────────
    cis_results_raw = []
    if "cis" in modules:
        _update_scan(db, scan_id, current_task="Running CIS Benchmark checks...", progress=55)
        try:
            cis_results_raw = run_cis_checks(aws_session, regions)
            cis_score = calculate_cis_score(cis_results_raw)
            cis_findings = cis_results_to_findings(cis_results_raw, scan_id)
            all_findings.extend(cis_findings)
            # Store full CIS results JSON on the scan
            _update_scan(db, scan_id,
                         cis_results=json.dumps(cis_results_raw),
                         cis_score=cis_score.get("overall_percent", 0))
        except Exception:
            pass

    # ── AI Enrichment ────────────────────────────────────────────────────────
    _update_scan(db, scan_id, current_task="AI enriching findings...", progress=68)
    enriched: list[dict] = []
    batch_size = 10
    for start in range(0, len(all_findings), batch_size):
        enriched.extend(enrich_findings_batch(all_findings[start: start + batch_size]))
    all_findings = enriched

    # ── Save findings ────────────────────────────────────────────────────────
    _update_scan(db, scan_id, current_task="Saving results...", progress=85)
    _save_findings(db, scan_id, all_findings)

    # ── Score + Summary ──────────────────────────────────────────────────────
    score, grade = _calculate_score(all_findings)
    sev_counts = {s: 0 for s in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in all_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    _update_scan(db, scan_id, current_task="Generating AI summary...", progress=92)
    summary = generate_scan_summary(all_findings, score, grade)

    _update_scan(
        db, scan_id,
        status="completed",
        progress=100,
        current_task="Complete",
        security_score=score,
        grade=grade,
        total_findings=len(all_findings),
        critical_count=sev_counts["Critical"],
        high_count=sev_counts["High"],
        medium_count=sev_counts["Medium"],
        low_count=sev_counts["Low"],
        ai_summary=summary,
        completed_at=datetime.utcnow(),
    )
