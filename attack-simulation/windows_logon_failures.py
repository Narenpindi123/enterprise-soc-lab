#!/usr/bin/env python3
"""
Windows Logon Failure Simulation
Generates Windows Security Event ID 4625 (failed logon) and 4624 (successful logon).
MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
"""

import os
import json
import random
import uuid
from datetime import datetime, timedelta

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "windows")

ATTACKER_IPS = ["198.51.100.23", "203.0.113.45"]
LEGITIMATE_IPS = ["10.0.1.100", "10.0.1.101", "10.0.2.50"]
WORKSTATION = "WS-FIN-PC04"
DOMAIN = "CORPSEC"
TARGET_ACCOUNTS = ["administrator", "svc_backup", "admin", "jsmith", "dbadmin", "sa", "guest", "user1"]
COMPROMISED_ACCOUNT = "svc_backup"

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "7": "Unlock",
    "10": "RemoteInteractive"
}

FAILURE_REASONS = [
    ("0xC000006D", "Bad username or authentication information"),
    ("0xC000006A", "An incorrect password was supplied"),
    ("0xC0000064", "The specified user does not exist"),
    ("0xC0000072", "The user account is disabled"),
    ("0xC0000234", "The user account has been locked out"),
]


def generate_event_4625(timestamp, src_ip, username, logon_type="10"):
    """Generate a Windows Event ID 4625 - Failed Logon."""
    failure = random.choice(FAILURE_REASONS)
    return {
        "EventID": 4625,
        "TimeCreated": timestamp.isoformat() + "Z",
        "Computer": f"{WORKSTATION}.{DOMAIN.lower()}.local",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Level": "Information",
        "Task": "Logon",
        "Keywords": "Audit Failure",
        "EventData": {
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "TargetUserName": username,
            "TargetDomainName": DOMAIN,
            "Status": failure[0],
            "FailureReason": failure[1],
            "SubStatus": "0x0",
            "LogonType": logon_type,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": WORKSTATION,
            "IpAddress": src_ip,
            "IpPort": str(random.randint(40000, 65000)),
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}"
        }
    }


def generate_event_4624(timestamp, src_ip, username, logon_type="10"):
    """Generate a Windows Event ID 4624 - Successful Logon."""
    return {
        "EventID": 4624,
        "TimeCreated": timestamp.isoformat() + "Z",
        "Computer": f"{WORKSTATION}.{DOMAIN.lower()}.local",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Level": "Information",
        "Task": "Logon",
        "Keywords": "Audit Success",
        "EventData": {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": WORKSTATION + "$",
            "SubjectDomainName": DOMAIN,
            "TargetUserSid": f"S-1-5-21-{random.randint(1000000, 9999999)}-{random.randint(1000, 9999)}",
            "TargetUserName": username,
            "TargetDomainName": DOMAIN,
            "LogonType": logon_type,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": WORKSTATION,
            "LogonGuid": "{" + str(uuid.uuid4()) + "}",
            "IpAddress": src_ip,
            "IpPort": str(random.randint(40000, 65000)),
            "ElevatedToken": "%%1842" if username == "administrator" else "%%1843"
        }
    }


def generate_windows_logon_logs(base_time=None):
    """Generate Windows logon failure and success logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    events = []
    attack_metadata = []
    
    # Legitimate logon activity (baseline noise)
    for i in range(25):
        ts = base_time + timedelta(minutes=random.randint(0, 2880))
        ip = random.choice(LEGITIMATE_IPS)
        user = random.choice(["jsmith", "svc_backup", "administrator"])
        lt = random.choice(["2", "3", "10"])
        events.append((ts, generate_event_4624(ts, ip, user, lt)))
    
    # Brute force attacks
    for attacker_ip in ATTACKER_IPS:
        attack_start = base_time + timedelta(
            hours=random.randint(2, 12),
            minutes=random.randint(0, 59)
        )
        
        attempt_count = random.randint(80, 200)
        for i in range(attempt_count):
            ts = attack_start + timedelta(seconds=i * random.uniform(0.3, 2.0))
            username = random.choice(TARGET_ACCOUNTS)
            events.append((ts, generate_event_4625(ts, attacker_ip, username, "10")))
        
        # Successful compromise
        success_time = attack_start + timedelta(seconds=attempt_count * 1.5 + random.randint(10, 60))
        events.append((success_time, generate_event_4624(success_time, attacker_ip, COMPROMISED_ACCOUNT, "10")))
        
        attack_metadata.append({
            "attack_type": "windows_brute_force",
            "mitre_technique": "T1110.001",
            "mitre_tactic": "Credential Access",
            "attacker_ip": attacker_ip,
            "target_host": WORKSTATION,
            "start_time": attack_start.isoformat(),
            "compromise_time": success_time.isoformat(),
            "compromised_account": COMPROMISED_ACCOUNT,
            "failed_attempts": attempt_count,
            "severity": "HIGH"
        })
    
    # Sort by timestamp
    events.sort(key=lambda x: x[0])
    
    # Write events
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    events_path = os.path.join(OUTPUT_DIR, "security_events.json")
    with open(events_path, "w") as f:
        json.dump([e[1] for e in events], f, indent=2)
    
    metadata_path = os.path.join(OUTPUT_DIR, "windows_bruteforce_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(attack_metadata, f, indent=2)
    
    print(f"[+] Generated {len(events)} Windows Security events → {events_path}")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return events, attack_metadata


if __name__ == "__main__":
    generate_windows_logon_logs()
