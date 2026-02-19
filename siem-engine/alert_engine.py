#!/usr/bin/env python3
"""
Alert Correlation Engine
Processes normalized log events through detection rules to generate alerts.
Includes event correlation, threshold-based detection, and threat intel enrichment.
"""

import os
import sys
import json
import uuid
import re
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from log_parser import normalize_all_logs
from detection_rules import DETECTION_RULES
from threat_intel import enrich_event, lookup_ip, lookup_domain, is_internal_ip

ALERTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts")
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def check_command_match(command, patterns):
    """Check if a command matches any suspicious patterns."""
    if not command or command == "unknown":
        return False
    command_lower = command.lower()
    for pattern in patterns:
        if pattern.lower() in command_lower:
            return True
        try:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False


def check_target_match(target, patterns):
    """Check if a target/path matches any patterns."""
    if not target or target == "unknown":
        return False
    for pattern in patterns:
        if pattern.lower() in target.lower():
            return True
    return False


def detect_threshold_alerts(events, rule):
    """Detect threshold-based alerts (e.g., brute force)."""
    alerts = []
    conditions = rule["conditions"]
    threshold = conditions.get("threshold", 5)
    time_window = conditions.get("time_window_minutes", 10)
    group_by = conditions.get("group_by", "")
    event_type = conditions.get("event_type", "")
    
    # Filter events matching this rule's source and event type
    source = rule.get("source", "")
    sources = [source] if isinstance(source, str) else source
    
    matching_events = []
    for e in events:
        if e.get("source") not in sources:
            continue
        if e.get("event_type") != event_type:
            continue
        
        # Check detail-level conditions
        if conditions.get("detail_match"):
            details = e.get("details", {})
            match = True
            for k, v in conditions["detail_match"].items():
                if details.get(k) != v:
                    match = False
                    break
            if not match:
                continue
        
        matching_events.append(e)
    
    if not matching_events:
        return alerts
    
    # Group events
    groups = defaultdict(list)
    for e in matching_events:
        key = ""
        if group_by:
            parts = group_by.split(".")
            val = e
            for part in parts:
                val = val.get(part, {}) if isinstance(val, dict) else ""
            key = str(val)
        else:
            key = "all"
        groups[key].append(e)
    
    # Check threshold per group
    for group_key, group_events in groups.items():
        if len(group_events) >= threshold:
            # Create alert
            alert = create_alert(rule, group_events, f"Threshold exceeded: {len(group_events)} events from {group_key}")
            alert["evidence"]["group_key"] = group_key
            alert["evidence"]["event_count"] = len(group_events)
            alerts.append(alert)
    
    return alerts


def detect_pattern_alerts(events, rule):
    """Detect pattern-based alerts (command matching, etc.)."""
    alerts = []
    conditions = rule["conditions"]
    event_type = conditions.get("event_type", "")
    
    source = rule.get("source", "")
    sources = [source] if isinstance(source, str) else source
    
    for e in events:
        if e.get("source") not in sources:
            continue
        
        e_type = e.get("event_type", "")
        if isinstance(event_type, list):
            if e_type not in event_type:
                continue
        elif e_type != event_type:
            continue
        
        details = e.get("details", {})
        matched = False
        
        # Check command_contains patterns
        if "command_contains" in conditions:
            command = details.get("command", details.get("command_line", ""))
            if check_command_match(command, conditions["command_contains"]):
                matched = True
        
        # Check target_contains patterns (registry, file paths)
        if "target_contains" in conditions:
            target = details.get("target_object", details.get("target", ""))
            if check_target_match(target, conditions["target_contains"]):
                matched = True
        
        # Check detail_match exact match
        if "detail_match" in conditions and not matched:
            match = True
            for k, v in conditions["detail_match"].items():
                if details.get(k) != v:
                    match = False
                    break
            if match:
                matched = True
        
        # Check param_contains (for CloudTrail)
        if "param_contains" in conditions:
            params = details.get("request_params", {})
            params_str = json.dumps(params)
            if conditions["param_contains"].lower() in params_str.lower():
                matched = True
        
        # Check region_not_in
        if "region_not_in" in conditions:
            region = details.get("region", "")
            if region and region not in conditions["region_not_in"]:
                matched = True
        
        # Check ip_not_in (external IP detection)
        if "ip_not_in" in conditions:
            ip = details.get("source_ip", "")
            if ip and not is_internal_ip(ip):
                matched = True
        
        if matched:
            alert = create_alert(rule, [e], f"Pattern match detected")
            alerts.append(alert)
    
    return alerts


def detect_sequence_alerts(events, rule):
    """Detect sequence-based alerts (e.g., success after failures)."""
    alerts = []
    conditions = rule["conditions"]
    
    source = rule.get("source", "")
    sources = [source] if isinstance(source, str) else source
    
    # Find IPs with many failures followed by success
    if "preceding_failures" in conditions:
        failures_by_ip = defaultdict(list)
        successes_by_ip = defaultdict(list)
        
        for e in events:
            if e.get("source") not in sources:
                continue
            ip = e.get("details", {}).get("source_ip", "")
            if not ip or ip == "unknown":
                continue
            
            if e.get("event_type") == "authentication_failure":
                failures_by_ip[ip].append(e)
            elif e.get("event_type") == "authentication_success":
                successes_by_ip[ip].append(e)
        
        min_failures = conditions.get("preceding_failures", 5)
        for ip, successes in successes_by_ip.items():
            if len(failures_by_ip.get(ip, [])) >= min_failures:
                evidence_events = failures_by_ip[ip][-3:] + successes[:1]
                alert = create_alert(
                    rule, evidence_events,
                    f"Successful login from {ip} after {len(failures_by_ip[ip])} failed attempts"
                )
                alert["evidence"]["failed_attempts"] = len(failures_by_ip[ip])
                alert["evidence"]["source_ip"] = ip
                alerts.append(alert)
    
    return alerts


def detect_threat_intel_alerts(events, rule):
    """Detect alerts based on threat intelligence matches."""
    alerts = []
    
    for e in events:
        if e.get("threat_intel"):
            for ti in e["threat_intel"]:
                if ti.get("found"):
                    alert = create_alert(rule, [e], f"Threat intel match: {ti['type']} {ti['indicator']}")
                    alert["evidence"]["threat_intel"] = ti
                    alerts.append(alert)
    
    return alerts


def create_alert(rule, evidence_events, detail_message):
    """Create an alert from a rule match."""
    timestamps = [e.get("timestamp", "") for e in evidence_events if e.get("timestamp")]
    
    alert = {
        "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "description": rule["description"],
        "severity": rule["severity"],
        "mitre_technique": rule["mitre_technique"],
        "mitre_tactic": rule["mitre_tactic"],
        "mitre_name": rule.get("mitre_name", ""),
        "timestamp": max(timestamps) if timestamps else datetime.now().isoformat(),
        "created_at": datetime.now().isoformat(),
        "triage_status": "NEW",
        "triage_classification": None,
        "analyst_notes": "",
        "detail": detail_message,
        "recommended_response": rule.get("response", ""),
        "evidence": {
            "event_count": len(evidence_events),
            "sample_events": [
                {
                    "event_id": e.get("event_id", ""),
                    "source": e.get("source", ""),
                    "event_type": e.get("event_type", ""),
                    "timestamp": e.get("timestamp", ""),
                    "details": e.get("details", {}),
                }
                for e in evidence_events[:5]
            ]
        }
    }
    
    return alert


def run_detection_engine():
    """Run the full detection engine pipeline."""
    print("=" * 70)
    print("  Enterprise SOC Lab - SIEM Alert Engine")
    print("  Processing logs and generating alerts...")
    print("=" * 70)
    print()
    
    # Step 1: Normalize all logs
    print("[Step 1] Normalizing logs from all sources...")
    events = normalize_all_logs()
    print()
    
    # Step 2: Enrich with threat intelligence
    print("[Step 2] Enriching events with threat intelligence...")
    ti_matches = 0
    for event in events:
        enrich_event(event)
        if event.get("threat_intel"):
            ti_matches += 1
    print(f"[+] Threat intel matches: {ti_matches}")
    print()
    
    # Step 3: Run detection rules
    print("[Step 3] Running detection rules...")
    all_alerts = []
    
    for rule in DETECTION_RULES:
        conditions = rule.get("conditions", {})
        
        # Determine detection type
        if "threshold" in conditions:
            alerts = detect_threshold_alerts(events, rule)
        elif "preceding_failures" in conditions:
            alerts = detect_sequence_alerts(events, rule)
        elif "ioc_match" in conditions:
            alerts = detect_threat_intel_alerts(events, rule)
        else:
            alerts = detect_pattern_alerts(events, rule)
        
        if alerts:
            print(f"  [!] {rule['rule_id']}: {rule['name']} → {len(alerts)} alert(s)")
            all_alerts.extend(alerts)
    
    print()
    
    # Deduplicate alerts (same rule + same source IP/host)
    seen = set()
    unique_alerts = []
    for alert in all_alerts:
        key = f"{alert['rule_id']}_{alert.get('evidence', {}).get('group_key', '')}_{alert.get('evidence', {}).get('source_ip', '')}"
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique_alerts.sort(key=lambda a: (severity_order.get(a["severity"], 5), a.get("timestamp", "")))
    
    # Write alerts
    os.makedirs(ALERTS_DIR, exist_ok=True)
    alerts_path = os.path.join(ALERTS_DIR, "alerts.json")
    with open(alerts_path, "w") as f:
        json.dump(unique_alerts, f, indent=2)
    
    # Write summary stats
    stats = {
        "total_events_processed": len(events),
        "threat_intel_matches": ti_matches,
        "total_alerts_generated": len(unique_alerts),
        "alerts_by_severity": {},
        "alerts_by_tactic": {},
        "detection_rules_triggered": len(set(a["rule_id"] for a in unique_alerts)),
        "total_detection_rules": len(DETECTION_RULES),
        "generated_at": datetime.now().isoformat()
    }
    
    for alert in unique_alerts:
        sev = alert["severity"]
        stats["alerts_by_severity"][sev] = stats["alerts_by_severity"].get(sev, 0) + 1
        tactic = alert["mitre_tactic"]
        stats["alerts_by_tactic"][tactic] = stats["alerts_by_tactic"].get(tactic, 0) + 1
    
    stats_path = os.path.join(ALERTS_DIR, "alert_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    
    # Print summary
    print("=" * 70)
    print(f"  ✅ Alert generation complete!")
    print(f"  📊 Total events processed: {len(events)}")
    print(f"  🔍 Threat intel matches: {ti_matches}")
    print(f"  🚨 Total alerts generated: {len(unique_alerts)}")
    print(f"  📁 Alerts → {alerts_path}")
    print(f"  📈 Stats → {stats_path}")
    print()
    
    print("  Alerts by Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats["alerts_by_severity"].get(sev, 0)
        if count > 0:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            print(f"    {emoji} {sev}: {count}")
    
    print()
    print("  Alerts by MITRE ATT&CK Tactic:")
    for tactic, count in sorted(stats["alerts_by_tactic"].items()):
        print(f"    ⚔️  {tactic}: {count}")
    
    print()
    print("=" * 70)
    print("  Next step: Start the SOC dashboard to triage alerts:")
    print("  $ cd dashboard && npm install && npm start")
    print("=" * 70)
    
    return unique_alerts, stats


if __name__ == "__main__":
    run_detection_engine()
