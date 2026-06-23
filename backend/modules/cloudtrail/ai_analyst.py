import json
import anthropic
from config import ANTHROPIC_API_KEY


def analyze_cloudtrail_with_ai(
    rule_findings: list[dict],
    events_summary: dict,
    malicious_ips: list[dict],
) -> dict:
    if not ANTHROPIC_API_KEY:
        return {
            "summary": "AI analysis unavailable — ANTHROPIC_API_KEY not configured.",
            "severity": "Info",
            "attack_assessment": "Configure ANTHROPIC_API_KEY to enable AI analysis.",
            "immediate_actions": [],
        }

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    findings_summary = [{"title": f["title"], "severity": f["severity"], "count": f.get("count", 1)}
                        for f in rule_findings]

    prompt = f"""You are an AWS security analyst reviewing CloudTrail log analysis results.

Events Summary:
- Total events: {events_summary.get('total_events', 0)}
- Unique users: {events_summary.get('unique_users', 0)}
- Unique IPs: {events_summary.get('unique_ips', 0)}
- Regions active: {events_summary.get('regions', [])}
- Top API calls: {events_summary.get('top_events', [])}

Rule-Based Findings ({len(rule_findings)} triggered):
{json.dumps(findings_summary, indent=2)}

Malicious IPs detected ({len(malicious_ips)}):
{json.dumps(malicious_ips, indent=2)}

Provide:
1. A plain English summary (2-3 sentences) of what happened in this log
2. Overall severity: Critical, High, Medium, or Low
3. Attack assessment: Active Attack / Suspicious Activity / Likely Benign / Normal Operations
4. 3-5 immediate actions to take

Return ONLY valid JSON in this exact format:
{{
  "summary": "...",
  "severity": "High",
  "attack_assessment": "Suspicious Activity",
  "immediate_actions": ["action 1", "action 2", "action 3"]
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)
    except Exception as e:
        return {
            "summary": f"AI analysis failed: {str(e)[:100]}",
            "severity": "Info",
            "attack_assessment": "Analysis failed",
            "immediate_actions": [],
        }
