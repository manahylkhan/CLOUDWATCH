import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from database import get_db
from models import Scan, Finding
from modules.cloudtrail.parser import parse_cloudtrail_file
from modules.cloudtrail.rules import apply_cloudtrail_rules, get_events_summary
from modules.cloudtrail.ip_checker import check_cloudtrail_ips
from modules.cloudtrail.ai_analyst import analyze_cloudtrail_with_ai

router = APIRouter(prefix="/api/cloudtrail", tags=["cloudtrail"])


@router.post("/{scan_id}/analyze")
async def analyze_cloudtrail(
    scan_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    content = await file.read()
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    try:
        events = parse_cloudtrail_file(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    rule_findings = apply_cloudtrail_rules(events)
    events_summary = get_events_summary(events)

    # IP reputation (async)
    try:
        malicious_ips = await check_cloudtrail_ips(events)
    except Exception:
        malicious_ips = []

    # AI analysis
    ai_result = analyze_cloudtrail_with_ai(rule_findings, events_summary, malicious_ips)

    # Save CloudTrail findings as Finding records
    for rf in rule_findings:
        finding = Finding(
            scan_id=scan_id,
            module="cloudtrail",
            service="CloudTrail",
            resource_id=rf.get("rule", "rule"),
            region="global",
            severity=rf["severity"],
            title=rf["title"],
            description=rf.get("description"),
            remediation=rf.get("remediation"),
        )
        db.add(finding)

    # Save malicious IP findings
    for ip_info in malicious_ips:
        finding = Finding(
            scan_id=scan_id,
            module="cloudtrail",
            service="CloudTrail",
            resource_id=ip_info["ip"],
            region="global",
            severity=ip_info["severity"],
            title=f"Malicious IP detected: {ip_info['ip']} (AbuseIPDB score: {ip_info['score']}%)",
            description=f"IP {ip_info['ip']} from {ip_info.get('country','?')} has an abuse confidence score of {ip_info['score']}%. ISP: {ip_info.get('isp','Unknown')}",
            remediation="Block this IP in your Security Groups and WAF. Investigate all actions taken from this IP.",
        )
        db.add(finding)

    # Update scan record
    db.query(Scan).filter(Scan.id == scan_id).update({
        "cloudtrail_summary": ai_result.get("summary", ""),
        "cloudtrail_severity": ai_result.get("severity", "Info"),
        "cloudtrail_assessment": ai_result.get("attack_assessment", ""),
        "cloudtrail_actions": json.dumps(ai_result.get("immediate_actions", [])),
        "cloudtrail_rule_findings": json.dumps([
            {"title": f["title"], "severity": f["severity"], "count": f.get("count", 1)}
            for f in rule_findings
        ]),
    })
    db.commit()

    return {
        "events_parsed": len(events),
        "rule_findings": len(rule_findings),
        "malicious_ips": len(malicious_ips),
        "ai_analysis": ai_result,
        "events_summary": events_summary,
    }
