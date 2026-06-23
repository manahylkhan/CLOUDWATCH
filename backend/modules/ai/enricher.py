import json
import anthropic
from config import ANTHROPIC_API_KEY

_client = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _client


def enrich_findings_batch(findings: list[dict]) -> list[dict]:
    if not findings or not ANTHROPIC_API_KEY:
        return findings

    client = _get_client()

    summaries = [
        {"index": i, "title": f["title"], "severity": f["severity"], "service": f["service"]}
        for i, f in enumerate(findings)
    ]

    prompt = f"""You are an AWS cloud security expert. For each of these security findings, write a clear 2-3 sentence plain English explanation a business owner can understand — no jargon.

Findings:
{json.dumps(summaries, indent=2)}

Return a JSON array with the same number of items, each with:
- index (same as input)
- explanation (2-3 sentences, plain English, business impact focused)
- effort (one of: Easy, Medium, Complex)

Return ONLY the JSON array, nothing else."""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        enriched = json.loads(raw)
        for item in enriched:
            idx = item["index"]
            if 0 <= idx < len(findings):
                findings[idx]["ai_explanation"] = item.get("explanation", "")
                findings[idx]["remediation_effort"] = item.get("effort", "Medium")
    except Exception:
        pass

    return findings


def generate_scan_summary(findings: list[dict], score: int, grade: str) -> str:
    if not ANTHROPIC_API_KEY:
        return ""

    client = _get_client()
    critical = [f for f in findings if f["severity"] == "Critical"]
    high = [f for f in findings if f["severity"] == "High"]

    prompt = f"""You are an AWS security expert. Write a 3-sentence executive summary for a security scan report.

Security score: {score}/100 (Grade {grade})
Critical findings: {len(critical)}
High findings: {len(high)}
Total findings: {len(findings)}

Top critical issues: {[f["title"] for f in critical[:3]]}

Write for a business executive — no technical jargon. Mention the score, most serious risk, and overall recommendation.
Return ONLY the 3 sentences, no headers or formatting."""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()
    except Exception:
        return ""
