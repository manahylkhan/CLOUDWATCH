import threading
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import AWSAccount, Scan, Finding
from modules.aws.credentials import decrypt_credential
from modules.aws.session import create_session, list_enabled_regions
from modules.scanner.orchestrator import run_full_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


class StartScanRequest(BaseModel):
    account_id: str
    modules: list[str] = ["misconfig"]


def _run_scan_thread(scan_id: str, account_id: str, modules: list[str]):
    from database import SessionLocal
    db = SessionLocal()
    try:
        account = db.query(AWSAccount).filter(AWSAccount.id == account_id).first()
        if not account:
            return
        access_key = decrypt_credential(account.access_key_encrypted)
        secret_key = decrypt_credential(account.secret_key_encrypted)
        session = create_session(access_key, secret_key, account.default_region)
        regions = list_enabled_regions(session) if account.scan_all_regions else [account.default_region]
        run_full_scan(scan_id, db, session, regions, modules)
        account.last_scan_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        db.query(Scan).filter(Scan.id == scan_id).update({
            "status": "failed",
            "current_task": f"Error: {str(e)[:200]}",
            "completed_at": datetime.utcnow(),
        })
        db.commit()
    finally:
        db.close()


@router.post("/start")
def start_scan(req: StartScanRequest, db: Session = Depends(get_db)):
    account = db.query(AWSAccount).filter(AWSAccount.id == req.account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="AWS account not found")
    scan = Scan(
        account_id=req.account_id,
        modules_run=",".join(req.modules),
        status="running",
        current_task="Starting scan...",
        progress=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    thread = threading.Thread(
        target=_run_scan_thread, args=(scan.id, req.account_id, req.modules), daemon=True
    )
    thread.start()
    return {"scan_id": scan.id, "status": "running"}


@router.get("/{scan_id}/status")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_dict(scan)


@router.get("/{scan_id}/findings")
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    module: Optional[str] = None,
    service: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if module:
        q = q.filter(Finding.module == module)
    if service:
        q = q.filter(Finding.service == service)
    findings = q.all()
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 5))
    return [f.to_dict() for f in findings]


@router.get("/")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    result = []
    for s in scans:
        account = db.query(AWSAccount).filter(AWSAccount.id == s.account_id).first()
        d = _scan_dict(s)
        d["account_alias"] = account.account_alias if account else "Unknown"
        d["account_id"] = account.account_id if account else "Unknown"
        result.append(d)
    return result


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    account = db.query(AWSAccount).filter(AWSAccount.id == scan.account_id).first()
    d = _scan_dict(scan)
    d["account_alias"] = account.account_alias if account else "Unknown"
    d["account_id"] = account.account_id if account else "Unknown"
    return d


def _scan_dict(scan: Scan) -> dict:
    import json
    cis_results = None
    if scan.cis_results:
        try:
            cis_results = json.loads(scan.cis_results)
        except Exception:
            pass
    return {
        "id": scan.id,
        "account_id": scan.account_id,
        "status": scan.status,
        "progress": scan.progress,
        "current_task": scan.current_task,
        "security_score": scan.security_score,
        "grade": scan.grade,
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "ai_summary": scan.ai_summary,
        "ai_roadmap": scan.ai_roadmap,
        "ai_chains": scan.ai_chains,
        "modules_run": scan.modules_run,
        "cis_results": cis_results,
        "cis_score": scan.cis_score,
        "cloudtrail_summary": scan.cloudtrail_summary,
        "cloudtrail_severity": scan.cloudtrail_severity,
        "cloudtrail_assessment": scan.cloudtrail_assessment,
        "cloudtrail_actions": json.loads(scan.cloudtrail_actions) if scan.cloudtrail_actions else [],
        "cloudtrail_rule_findings": json.loads(scan.cloudtrail_rule_findings) if scan.cloudtrail_rule_findings else [],
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
