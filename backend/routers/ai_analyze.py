import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Scan, Finding
from modules.ai.risk_prioritizer import prioritize_all_findings

router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.post("/{scan_id}/prioritize")
def run_ai_prioritization(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_dicts = [f.to_dict() for f in findings]

    result = prioritize_all_findings(findings_dicts)

    # Update AI explanations on findings
    for enriched in result.get("enriched_findings", []):
        fid = enriched.get("id")
        if fid:
            update_data = {}
            if enriched.get("explanation"):
                update_data["ai_explanation"] = enriched["explanation"]
            if enriched.get("effort"):
                update_data["remediation_effort"] = enriched["effort"]
            if update_data:
                db.query(Finding).filter(Finding.id == fid).update(update_data)

    # Save to scan
    db.query(Scan).filter(Scan.id == scan_id).update({
        "ai_summary": result.get("executive_summary", scan.ai_summary),
        "ai_roadmap": json.dumps(result.get("fix_roadmap", {})),
        "ai_chains": json.dumps(result.get("risk_chains", [])),
    })
    db.commit()

    return {
        "executive_summary": result.get("executive_summary", ""),
        "fix_roadmap": result.get("fix_roadmap", {}),
        "risk_chains": result.get("risk_chains", []),
        "findings_enriched": len(result.get("enriched_findings", [])),
    }
