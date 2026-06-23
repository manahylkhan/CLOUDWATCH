import json
import anthropic
from config import ANTHROPIC_API_KEY


def prioritize_all_findings(findings: list[dict]) -> dict:
    if not ANTHROPIC_API_KEY:
        return {
            "enriched_findings": [],
            "risk_chains": [],
            "executive_summary": "Configure ANTHROPIC_API_KEY to enable AI risk prioritization.",
            "fix_roadmap": {"immediate": [], "this_week": [], "this_month": []},
        }

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    critical_high = [f for f in findings if f.get("severity") in ("Critical", "High")][:30]

    if not critical_high:
        return {
            "enriched_findings": [],
            "risk_chains": [],
            "executive_summary": "No Critical or High findings detected. Your AWS environment is in good shape.",
            "fix_roadmap": {"immediate": [], "this_week": [], "this_month": []},
        }

    compact = [
        {
            "id": f.get("id", str(i)),
            "title": f["title"],
            "severity": f["severity"],
            "service": f.get("service", ""),
            "module": f.get("module", ""),
        }
        for i, f in enumerate(critical_high)
    ]

    prompt = f"""You are an AWS cloud security expert. Analyze these {len(compact)} Critical and High findings from an AWS security audit.

Findings:
{json.dumps(compact, indent=2)}

Return ONLY valid JSON with this exact structure:
{{
  "enriched_findings": [
    {{
      "id": "finding id",
      "explanation": "2-3 sentence plain English explanation a CEO understands",
      "impact": "specific real-world consequence if exploited",
      "effort": "Easy|Medium|Complex",
      "priority": 1
    }}
  ],
  "risk_chains": [
    {{
      "name": "chain name",
      "finding_titles": ["title1", "title2"],
      "combined_risk": "why these together are worse",
      "scenario": "specific attack scenario using these together"
    }}
  ],
  "executive_summary": "3 sentences for management — no jargon, focus on business risk and overall recommendation",
  "fix_roadmap": {{
    "immediate": ["specific action 1", "specific action 2"],
    "this_week": ["specific action 3"],
    "this_month": ["specific action 4"]
  }}
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
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
            "enriched_findings": [],
            "risk_chains": [],
            "executive_summary": f"AI analysis failed: {str(e)[:200]}",
            "fix_roadmap": {"immediate": [], "this_week": [], "this_month": []},
        }
