import json


def parse_cloudtrail_file(file_content: str) -> list[dict]:
    try:
        data = json.loads(file_content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    records = data.get("Records", [])
    if not records:
        raise ValueError("No 'Records' array found in CloudTrail file.")

    parsed = []
    for event in records:
        parsed.append({
            "event_id": event.get("eventID"),
            "event_time": event.get("eventTime"),
            "event_name": event.get("eventName", ""),
            "event_source": event.get("eventSource", ""),
            "source_ip": event.get("sourceIPAddress", ""),
            "user_agent": event.get("userAgent", ""),
            "user_type": event.get("userIdentity", {}).get("type", ""),
            "user_name": event.get("userIdentity", {}).get("userName", "unknown"),
            "error_code": event.get("errorCode"),
            "aws_region": event.get("awsRegion", ""),
            "request_params": json.dumps(event.get("requestParameters") or {}),
        })

    return parsed
