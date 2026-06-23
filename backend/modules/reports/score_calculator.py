import json
from datetime import datetime

from sqlalchemy.orm import Session
from models import Scan, Finding
from config import SEVERITY_DEDUCTIONS


def calculate_final_score(scan_id: str, db: Session) -> dict:
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    module_scores = {}
    for module in ("misconfig", "iam", "cloudtrail", "cis"):
        mf = [f for f in findings if f.module == module]
        ms = 100
        for f in mf:
            ms -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
        module_scores[module] = max(0, ms)

    counts = {sev: sum(1 for f in findings if f.severity == sev)
              for sev in ("Critical", "High", "Medium", "Low", "Info")}

    db.query(Scan).filter(Scan.id == scan_id).update({
        "security_score": score,
        "grade": grade,
        "total_findings": len(findings),
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
    })
    db.commit()

    return {"score": score, "grade": grade, "module_scores": module_scores, "counts": counts}
