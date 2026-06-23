import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from database import get_db
from models import Scan, Finding, AWSAccount
from modules.reports.pdf_generator import generate_pdf_report
from modules.reports.word_generator import generate_word_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _load_scan_data(scan_id: str, db: Session):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    account = db.query(AWSAccount).filter(AWSAccount.id == scan.account_id).first()

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_dicts = [f.to_dict() for f in findings]

    scan_dict = {
        "id": scan.id,
        "account_alias": account.account_alias if account else "Unknown",
        "account_id": account.account_id if account else "Unknown",
        "security_score": scan.security_score,
        "grade": scan.grade,
        "total_findings": scan.total_findings,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "ai_summary": scan.ai_summary,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
    }

    cis_results = None
    if scan.cis_results:
        try:
            cis_results = json.loads(scan.cis_results)
        except Exception:
            pass

    ai_roadmap = None
    if scan.ai_roadmap:
        try:
            ai_roadmap = json.loads(scan.ai_roadmap)
        except Exception:
            pass

    return scan_dict, findings_dicts, cis_results, ai_roadmap


@router.get("/{scan_id}/pdf")
def download_pdf(
    scan_id: str,
    client_name: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    scan_dict, findings, cis_results, ai_roadmap = _load_scan_data(scan_id, db)
    try:
        pdf_bytes = generate_pdf_report(
            scan=scan_dict,
            findings=findings,
            cis_results=cis_results,
            client_name=client_name,
            ai_roadmap=ai_roadmap,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    filename = f"CLOUDWATCH-Report-{scan_dict['account_alias'].replace(' ', '_')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/word")
def download_word(
    scan_id: str,
    client_name: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    scan_dict, findings, cis_results, ai_roadmap = _load_scan_data(scan_id, db)
    try:
        docx_bytes = generate_word_report(
            scan=scan_dict,
            findings=findings,
            cis_results=cis_results,
            client_name=client_name,
            ai_roadmap=ai_roadmap,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Word generation failed: {e}")

    filename = f"CLOUDWATCH-Report-{scan_dict['account_alias'].replace(' ', '_')}.docx"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
