import httpx
from config import ABUSEIPDB_API_KEY


async def check_cloudtrail_ips(events: list[dict]) -> list[dict]:
    unique_ips = list({
        e["source_ip"] for e in events
        if e["source_ip"] and not e["source_ip"].startswith("AWS")
    })[:20]

    if not unique_ips or not ABUSEIPDB_API_KEY:
        return []

    results = []
    async with httpx.AsyncClient(timeout=10) as client:
        for ip in unique_ips:
            try:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    if score > 25:
                        results.append({
                            "ip": ip,
                            "score": score,
                            "country": data.get("countryCode", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "total_reports": data.get("totalReports", 0),
                            "severity": "Critical" if score > 75 else "High",
                        })
            except Exception:
                pass

    return results
