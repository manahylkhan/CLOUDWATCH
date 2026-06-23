from collections import defaultdict


_DELETE_KEYWORDS = ("Delete", "Terminate", "Remove", "Destroy", "Deregister")
_DISABLE_EVENTS = {
    "StopLogging", "DeleteTrail", "DisableAlarmActions",
    "DeleteAlarms", "PutBucketLogging", "DeleteFlowLogs",
}
_ESCALATION_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy", "CreateAccessKey",
    "AddUserToGroup", "UpdateAssumeRolePolicy", "PutUserPolicy",
    "PutGroupPolicy", "CreatePolicy", "CreatePolicyVersion",
}
_FAILED_AUTH_CODES = {"InvalidClientTokenId", "UnauthorizedOperation", "AccessDenied"}
_RECON_PREFIXES = ("List", "Describe", "Get", "Enumerate")


def apply_cloudtrail_rules(events: list[dict]) -> list[dict]:
    findings = []

    # RULE 1: Root account usage
    root_events = [e for e in events if e["user_type"] == "Root"]
    if root_events:
        findings.append({
            "rule": "root_usage",
            "severity": "Critical",
            "title": f"Root account used {len(root_events)} time(s)",
            "description": "The root account was used for API calls. Root should never be used for operations.",
            "remediation": "Stop using the root account. Use IAM users with appropriate permissions.",
            "events": root_events[:5],
            "count": len(root_events),
        })

    # RULE 2: Mass deletion events
    deletions = [e for e in events if any(k in e["event_name"] for k in _DELETE_KEYWORDS)]
    if len(deletions) > 10:
        findings.append({
            "rule": "mass_deletion",
            "severity": "High",
            "title": f"Mass deletion activity: {len(deletions)} delete events detected",
            "description": "An unusually high number of delete/terminate operations occurred. This could indicate ransomware or insider threat.",
            "remediation": "Review the deletion events and check if they were authorized. Enable S3 versioning and MFA delete.",
            "events": deletions[:5],
            "count": len(deletions),
        })

    # RULE 3: Security tool disabling
    for ev in events:
        if ev["event_name"] in _DISABLE_EVENTS:
            findings.append({
                "rule": "security_disabled",
                "severity": "Critical",
                "title": f"Security tool disabled: {ev['event_name']} by {ev['user_name']}",
                "description": f"{ev['event_name']} was called — attackers disable logging/monitoring to hide their tracks.",
                "remediation": "Investigate why this security tool was disabled. Re-enable immediately and audit the caller.",
                "events": [ev],
                "count": 1,
            })

    # RULE 4: IAM privilege escalation
    escalations = [e for e in events if e["event_name"] in _ESCALATION_EVENTS]
    if escalations:
        findings.append({
            "rule": "iam_escalation",
            "severity": "High",
            "title": f"IAM permission changes: {len(escalations)} event(s) detected",
            "description": "IAM policy changes or privilege grants were detected. These could indicate privilege escalation.",
            "remediation": "Review all IAM changes and verify they were authorized. Check if any new admin access was granted.",
            "events": escalations[:5],
            "count": len(escalations),
        })

    # RULE 5: Failed auth / brute force
    failed_auths = [e for e in events if e.get("error_code") in _FAILED_AUTH_CODES]
    ip_fails: dict[str, list] = defaultdict(list)
    for e in failed_auths:
        ip_fails[e["source_ip"]].append(e)
    for ip, fails in ip_fails.items():
        if len(fails) > 10:
            findings.append({
                "rule": "brute_force",
                "severity": "Medium",
                "title": f"Repeated auth failures from {ip}: {len(fails)} failures",
                "description": f"IP {ip} generated {len(fails)} authentication failures. This pattern suggests a brute force or credential stuffing attack.",
                "remediation": "Block IP in security groups/WAF. Enable account lockout. Check for compromised credentials.",
                "events": fails[:3],
                "count": len(fails),
            })

    # RULE 6: Reconnaissance — rapid List/Describe calls
    recon_events = [e for e in events if any(e["event_name"].startswith(k) for k in _RECON_PREFIXES)]
    ip_recon: dict[str, list] = defaultdict(list)
    for e in recon_events:
        if e["source_ip"] and not e["source_ip"].startswith("AWS"):
            ip_recon[e["source_ip"]].append(e)
    for ip, recon in ip_recon.items():
        if len(recon) > 50:
            findings.append({
                "rule": "reconnaissance",
                "severity": "Medium",
                "title": f"Possible reconnaissance from {ip}: {len(recon)} List/Describe calls",
                "description": f"IP {ip} made {len(recon)} enumeration calls in rapid succession. Attackers map AWS environments before attacking.",
                "remediation": "Review if this IP is expected. Block if unauthorized. Enable GuardDuty for automated detection.",
                "events": recon[:3],
                "count": len(recon),
            })

    # RULE 7: Unusual hours activity (simple heuristic — after 10pm UTC)
    night_events = []
    for e in events:
        et = e.get("event_time", "")
        if et and "T" in et:
            try:
                hour = int(et.split("T")[1][:2])
                if 22 <= hour or hour < 5:
                    night_events.append(e)
            except (ValueError, IndexError):
                pass
    if len(night_events) > 20:
        findings.append({
            "rule": "off_hours",
            "severity": "Low",
            "title": f"Off-hours activity: {len(night_events)} API calls between 10pm–5am UTC",
            "description": "Significant API activity was detected during late night hours. This may warrant investigation if not from automated systems.",
            "remediation": "Review if this activity is from automated processes or scheduled jobs. Investigate if unexpected.",
            "events": night_events[:3],
            "count": len(night_events),
        })

    # RULE 8: Cross-region activity
    regions_seen = set(e["aws_region"] for e in events if e["aws_region"])
    if len(regions_seen) > 5:
        findings.append({
            "rule": "cross_region",
            "severity": "Low",
            "title": f"Activity across {len(regions_seen)} regions: {', '.join(sorted(regions_seen)[:6])}",
            "description": "API calls were made across many regions. Attackers often spread activity across regions to avoid detection.",
            "remediation": "Verify if multi-region activity is expected. Consider restricting access to specific regions via IAM conditions.",
            "events": [],
            "count": len(regions_seen),
        })

    return findings


def get_events_summary(events: list[dict]) -> dict:
    total = len(events)
    unique_users = len(set(e["user_name"] for e in events))
    unique_ips = len(set(e["source_ip"] for e in events if e["source_ip"]))
    regions = list(set(e["aws_region"] for e in events if e["aws_region"]))
    top_events: dict[str, int] = defaultdict(int)
    for e in events:
        top_events[e["event_name"]] += 1
    top_5 = sorted(top_events.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "total_events": total,
        "unique_users": unique_users,
        "unique_ips": unique_ips,
        "regions": regions,
        "top_events": [{"name": k, "count": v} for k, v in top_5],
    }
