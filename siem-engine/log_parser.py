#!/usr/bin/env python3
"""
Unified Log Parser and Normalizer
Parses all log formats (syslog, Windows XML/JSON, CloudTrail, DNS, proxy)
into a unified schema for the alert engine.
"""

import os
import re
import json
from datetime import datetime

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")


def parse_auth_log(filepath):
    """Parse Linux auth.log entries into normalized format."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            event = {
                "source": "linux_auth",
                "raw": line,
                "log_file": filepath,
                "line_number": line_num,
            }
            
            # Extract timestamp
            ts_match = re.match(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if ts_match:
                try:
                    ts = datetime.strptime(f"2026 {ts_match.group(1)}", "%Y %b %d %H:%M:%S")
                    event["timestamp"] = ts.isoformat()
                except ValueError:
                    event["timestamp"] = datetime.now().isoformat()
            
            # Classify event type
            if "Failed password" in line:
                event["event_type"] = "authentication_failure"
                event["severity"] = "MEDIUM"
                ip_match = re.search(r'from\s+(\S+)\s+port', line)
                user_match = re.search(r'for\s+(?:invalid user\s+)?(\S+)\s+from', line)
                event["details"] = {
                    "source_ip": ip_match.group(1) if ip_match else "unknown",
                    "username": user_match.group(1) if user_match else "unknown",
                    "service": "sshd",
                    "action": "failed_login"
                }
            elif "Accepted password" in line:
                event["event_type"] = "authentication_success"
                event["severity"] = "INFO"
                ip_match = re.search(r'from\s+(\S+)\s+port', line)
                user_match = re.search(r'for\s+(\S+)\s+from', line)
                event["details"] = {
                    "source_ip": ip_match.group(1) if ip_match else "unknown",
                    "username": user_match.group(1) if user_match else "unknown",
                    "service": "sshd",
                    "action": "successful_login"
                }
            elif "sudo:" in line and "COMMAND=" in line:
                event["event_type"] = "privilege_escalation"
                event["severity"] = "MEDIUM"
                user_match = re.search(r'sudo:\s+(\S+)\s+:', line)
                cmd_match = re.search(r'COMMAND=(.+)$', line)
                not_sudoers = "NOT in sudoers" in line
                event["details"] = {
                    "username": user_match.group(1) if user_match else "unknown",
                    "command": cmd_match.group(1) if cmd_match else "unknown",
                    "action": "sudo_denied" if not_sudoers else "sudo_executed",
                    "unauthorized": not_sudoers
                }
                if not_sudoers:
                    event["severity"] = "HIGH"
            elif "CRON[" in line:
                event["event_type"] = "scheduled_task"
                event["severity"] = "LOW"
                cmd_match = re.search(r'CMD\s+\((.+)\)', line)
                event["details"] = {
                    "action": "cron_execution",
                    "command": cmd_match.group(1) if cmd_match else "unknown"
                }
            elif "crontab[" in line:
                event["event_type"] = "scheduled_task_modified"
                event["severity"] = "MEDIUM"
                user_match = re.search(r'\((\S+)\)\s+REPLACE', line)
                event["details"] = {
                    "action": "crontab_modified",
                    "username": user_match.group(1) if user_match else "unknown"
                }
            elif "systemd" in line:
                event["event_type"] = "service_activity"
                event["severity"] = "LOW"
                event["details"] = {
                    "action": "systemd_activity",
                    "message": line.split("systemd")[-1].strip() if "systemd" in line else line
                }
            elif "su:" in line:
                event["event_type"] = "privilege_escalation"
                event["severity"] = "MEDIUM"
                if "FAILED" in line:
                    event["severity"] = "HIGH"
                    event["details"] = {"action": "su_failed"}
                else:
                    event["details"] = {"action": "su_success"}
            else:
                event["event_type"] = "other"
                event["severity"] = "LOW"
                event["details"] = {"message": line}
            
            events.append(event)
    
    return events


def parse_windows_security_events(filepath):
    """Parse Windows Security events JSON."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        raw_events = json.load(f)
    
    for raw in raw_events:
        event = {
            "source": "windows_security",
            "timestamp": raw.get("TimeCreated", "").replace("Z", ""),
            "raw": json.dumps(raw),
            "log_file": filepath,
        }
        
        event_id = raw.get("EventID")
        event_data = raw.get("EventData", {})
        
        if event_id == 4625:
            event["event_type"] = "authentication_failure"
            event["severity"] = "MEDIUM"
            event["details"] = {
                "source_ip": event_data.get("IpAddress", "unknown"),
                "username": event_data.get("TargetUserName", "unknown"),
                "domain": event_data.get("TargetDomainName", "unknown"),
                "logon_type": event_data.get("LogonType", "unknown"),
                "failure_reason": event_data.get("FailureReason", "unknown"),
                "service": "windows_logon",
                "action": "failed_login"
            }
        elif event_id == 4624:
            event["event_type"] = "authentication_success"
            event["severity"] = "INFO"
            event["details"] = {
                "source_ip": event_data.get("IpAddress", "unknown"),
                "username": event_data.get("TargetUserName", "unknown"),
                "domain": event_data.get("TargetDomainName", "unknown"),
                "logon_type": event_data.get("LogonType", "unknown"),
                "service": "windows_logon",
                "action": "successful_login"
            }
        elif event_id == 4688:
            event["event_type"] = "process_creation"
            event["severity"] = "LOW"
            event["details"] = {
                "username": event_data.get("SubjectUserName", "unknown"),
                "command_line": event_data.get("CommandLine", "unknown"),
                "process_name": event_data.get("NewProcessName", "unknown"),
                "parent_process": event_data.get("ParentProcessName", "unknown"),
                "action": "process_created"
            }
        else:
            event["event_type"] = "other"
            event["severity"] = "LOW"
            event["details"] = {"event_id": event_id}
        
        events.append(event)
    
    return events


def parse_sysmon_events(filepath):
    """Parse Windows Sysmon events JSON."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        raw_events = json.load(f)
    
    for raw in raw_events:
        event_data = raw.get("EventData", {})
        event = {
            "source": "windows_sysmon",
            "timestamp": raw.get("TimeCreated", "").replace("Z", ""),
            "raw": json.dumps(raw),
            "log_file": filepath,
            "event_type": "registry_modification" if raw.get("EventID") == 13 else "sysmon_event",
            "severity": "MEDIUM",
            "details": {
                "event_type": event_data.get("EventType", "unknown"),
                "image": event_data.get("Image", "unknown"),
                "target_object": event_data.get("TargetObject", "unknown"),
                "details": event_data.get("Details", "unknown"),
                "user": event_data.get("User", "unknown"),
                "action": "registry_value_set"
            }
        }
        events.append(event)
    
    return events


def parse_cloudtrail_events(filepath):
    """Parse AWS CloudTrail events JSON."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        data = json.load(f)
    
    records = data.get("Records", data) if isinstance(data, dict) else data
    
    for raw in records:
        event = {
            "source": "aws_cloudtrail",
            "timestamp": raw.get("eventTime", "").replace("Z", ""),
            "raw": json.dumps(raw),
            "log_file": filepath,
            "event_type": "cloud_api_call",
            "severity": "LOW",
            "details": {
                "event_name": raw.get("eventName", "unknown"),
                "event_source": raw.get("eventSource", "unknown"),
                "source_ip": raw.get("sourceIPAddress", "unknown"),
                "user_name": raw.get("userIdentity", {}).get("userName", "unknown"),
                "region": raw.get("awsRegion", "unknown"),
                "access_key": raw.get("userIdentity", {}).get("accessKeyId", "unknown"),
                "request_params": raw.get("requestParameters", {}),
                "error_code": raw.get("errorCode"),
                "action": raw.get("eventName", "unknown")
            }
        }
        
        # Elevate severity for write operations
        if not raw.get("readOnly", True):
            event["severity"] = "MEDIUM"
        if raw.get("errorCode"):
            event["severity"] = "MEDIUM"
        
        events.append(event)
    
    return events


def parse_dns_log(filepath):
    """Parse DNS query logs."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            query_match = re.search(r'query:\s+(\S+)\s+IN\s+(\S+)', line)
            client_match = re.search(r'client\s+\S+\s+(\S+)#', line)
            
            event = {
                "source": "dns",
                "raw": line,
                "log_file": filepath,
                "line_number": line_num,
                "event_type": "dns_query",
                "severity": "LOW",
                "details": {
                    "query_domain": query_match.group(1) if query_match else "unknown",
                    "query_type": query_match.group(2) if query_match else "unknown",
                    "source_ip": client_match.group(1) if client_match else "unknown",
                    "action": "dns_lookup"
                }
            }
            
            # Check for suspiciously long subdomains (DNS tunneling indicator)
            if query_match:
                domain = query_match.group(1)
                subdomain_parts = domain.split(".")
                if any(len(part) > 30 for part in subdomain_parts):
                    event["severity"] = "HIGH"
                    event["details"]["suspicious"] = True
                    event["details"]["reason"] = "unusually_long_subdomain"
            
            # Extract timestamp
            ts_match = re.match(r'(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)', line)
            if ts_match:
                try:
                    ts = datetime.strptime(ts_match.group(1)[:20], "%d-%b-%Y %H:%M:%S")
                    event["timestamp"] = ts.isoformat()
                except ValueError:
                    event["timestamp"] = datetime.now().isoformat()
            
            events.append(event)
    
    return events


def parse_proxy_log(filepath):
    """Parse proxy/web filter access logs."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            event = {
                "source": "proxy",
                "raw": line,
                "log_file": filepath,
                "line_number": line_num,
                "event_type": "web_request",
                "severity": "LOW",
                "timestamp": parts[0] if parts else datetime.now().isoformat(),
                "details": {
                    "source_ip": parts[2] if len(parts) > 2 else "unknown",
                    "method": parts[5] if len(parts) > 5 else "unknown",
                    "url": parts[6] if len(parts) > 6 else "unknown",
                    "bytes": int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                    "status": parts[3].split("/")[-1] if len(parts) > 3 else "unknown",
                    "action": "web_access"
                }
            }
            
            # Check for large uploads (potential exfiltration)
            if event["details"]["method"] == "POST":
                try:
                    bytes_val = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
                    if bytes_val > 100000:
                        event["severity"] = "HIGH"
                        event["details"]["suspicious"] = True
                        event["details"]["reason"] = "large_outbound_data_transfer"
                except (ValueError, IndexError):
                    pass
            
            events.append(event)
    
    return events


def parse_s3_access_events(filepath):
    """Parse S3 access events JSON."""
    events = []
    if not os.path.exists(filepath):
        return events
    
    with open(filepath) as f:
        raw_events = json.load(f)
    
    for raw in raw_events:
        bytes_out = raw.get("additionalEventData", {}).get("bytesTransferredOut", 0)
        event = {
            "source": "aws_s3",
            "timestamp": raw.get("eventTime", "").replace("Z", ""),
            "raw": json.dumps(raw),
            "log_file": filepath,
            "event_type": "s3_access",
            "severity": "LOW",
            "details": {
                "event_name": raw.get("eventName", "unknown"),
                "source_ip": raw.get("sourceIPAddress", "unknown"),
                "user_name": raw.get("userIdentity", {}).get("userName", "unknown") if raw.get("userIdentity") else "unknown",
                "bucket_name": raw.get("requestParameters", {}).get("bucketName", "unknown"),
                "key": raw.get("requestParameters", {}).get("key", ""),
                "bytes_transferred": bytes_out,
                "action": raw.get("eventName", "unknown")
            }
        }
        
        # High severity for large data transfers
        if bytes_out > 1000000:
            event["severity"] = "HIGH"
            event["details"]["suspicious"] = True
            event["details"]["reason"] = "large_data_download"
        
        events.append(event)
    
    return events


def normalize_all_logs():
    """Parse and normalize all log sources."""
    all_events = []
    
    # Linux logs
    auth_log = os.path.join(LOGS_DIR, "linux", "auth.log")
    all_events.extend(parse_auth_log(auth_log))
    
    # Windows logs
    security_events = os.path.join(LOGS_DIR, "windows", "security_events.json")
    all_events.extend(parse_windows_security_events(security_events))
    
    sysmon_events = os.path.join(LOGS_DIR, "windows", "sysmon_events.json")
    all_events.extend(parse_sysmon_events(sysmon_events))
    
    # Cloud logs
    cloudtrail = os.path.join(LOGS_DIR, "cloud", "cloudtrail_events.json")
    all_events.extend(parse_cloudtrail_events(cloudtrail))
    
    s3_access = os.path.join(LOGS_DIR, "cloud", "s3_access_events.json")
    all_events.extend(parse_s3_access_events(s3_access))
    
    # Network logs
    dns_log = os.path.join(LOGS_DIR, "network", "dns_queries.log")
    all_events.extend(parse_dns_log(dns_log))
    
    proxy_log = os.path.join(LOGS_DIR, "network", "proxy_access.log")
    all_events.extend(parse_proxy_log(proxy_log))
    
    # Sort by timestamp
    all_events.sort(key=lambda x: x.get("timestamp", ""))
    
    # Assign IDs
    for i, event in enumerate(all_events):
        event["event_id"] = f"EVT-{i+1:06d}"
    
    # Write normalized events
    output_path = os.path.join(LOGS_DIR, "normalized_events.json")
    with open(output_path, "w") as f:
        json.dump(all_events, f, indent=2)
    
    print(f"[+] Normalized {len(all_events)} events from all sources → {output_path}")
    
    # Print summary
    sources = {}
    for e in all_events:
        src = e.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1
    
    print("[+] Event breakdown by source:")
    for src, count in sorted(sources.items()):
        print(f"    {src}: {count}")
    
    return all_events


if __name__ == "__main__":
    normalize_all_logs()
