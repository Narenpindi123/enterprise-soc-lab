#!/usr/bin/env python3
"""
SSH Brute Force Attack Simulation
Generates realistic Linux auth.log entries simulating an SSH brute force attack.
MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing
"""

import os
import json
import random
from datetime import datetime, timedelta

# Configuration
ATTACKER_IPS = ["198.51.100.23", "203.0.113.45", "192.0.2.100"]
LEGITIMATE_IPS = ["10.0.1.50", "10.0.1.51", "10.0.2.10", "172.16.0.5"]
TARGET_HOST = "prod-web-01"
USERNAMES_TRIED = ["root", "admin", "ubuntu", "deploy", "backup", "postgres", "mysql", "www-data", "oracle", "test"]
VALID_USER = "deploy"
SSH_PORT = 22

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "linux")


def generate_failed_ssh(timestamp, src_ip, username, pid):
    """Generate a failed SSH login auth.log entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {TARGET_HOST} sshd[{pid}]: Failed password for {'invalid user ' if username not in ['root', 'deploy', 'ubuntu'] else ''}{username} from {src_ip} port {random.randint(40000, 65000)} ssh2"


def generate_successful_ssh(timestamp, src_ip, username, pid):
    """Generate a successful SSH login auth.log entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {TARGET_HOST} sshd[{pid}]: Accepted password for {username} from {src_ip} port {random.randint(40000, 65000)} ssh2"


def generate_session_opened(timestamp, username, pid):
    """Generate a session opened log entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {TARGET_HOST} sshd[{pid}]: pam_unix(sshd:session): session opened for user {username}(uid=1001) by (uid=0)"


def generate_connection_closed(timestamp, src_ip, pid):
    """Generate a connection closed entry."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    return f"{ts} {TARGET_HOST} sshd[{pid}]: Connection closed by {src_ip} port {random.randint(40000, 65000)} [preauth]"


def generate_legitimate_activity(base_time, logs):
    """Generate normal SSH activity for baseline noise."""
    for i in range(15):
        ts = base_time + timedelta(minutes=random.randint(0, 1440))
        ip = random.choice(LEGITIMATE_IPS)
        user = random.choice(["deploy", "ubuntu"])
        pid = random.randint(10000, 30000)
        logs.append((ts, generate_successful_ssh(ts, ip, user, pid)))
        logs.append((ts + timedelta(seconds=1), generate_session_opened(ts + timedelta(seconds=1), user, pid)))


def generate_brute_force_attack(base_time, attacker_ip, logs):
    """Generate an SSH brute force attack sequence."""
    attack_start = base_time + timedelta(
        hours=random.randint(1, 6),
        minutes=random.randint(0, 59)
    )
    
    pid = random.randint(20000, 40000)
    attempt_count = random.randint(50, 150)
    
    for i in range(attempt_count):
        ts = attack_start + timedelta(seconds=i * random.uniform(0.5, 3.0))
        username = random.choice(USERNAMES_TRIED)
        pid_offset = pid + i
        logs.append((ts, generate_failed_ssh(ts, attacker_ip, username, pid_offset)))
        
        if random.random() < 0.3:
            logs.append((ts + timedelta(milliseconds=500), generate_connection_closed(ts + timedelta(milliseconds=500), attacker_ip, pid_offset)))
    
    # Successful login after brute force (attacker gets in)
    success_time = attack_start + timedelta(seconds=attempt_count * 2 + random.randint(5, 30))
    final_pid = pid + attempt_count + 1
    logs.append((success_time, generate_successful_ssh(success_time, attacker_ip, VALID_USER, final_pid)))
    logs.append((success_time + timedelta(seconds=1), generate_session_opened(success_time + timedelta(seconds=1), VALID_USER, final_pid)))
    
    return attack_start, success_time


def generate_ssh_bruteforce_logs(base_time=None):
    """Main function to generate all SSH brute force logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    logs = []
    attack_metadata = []
    
    # Generate legitimate baseline activity
    generate_legitimate_activity(base_time, logs)
    
    # Generate brute force attacks from multiple IPs
    for attacker_ip in ATTACKER_IPS:
        start, success = generate_brute_force_attack(base_time, attacker_ip, logs)
        attack_metadata.append({
            "attack_type": "ssh_brute_force",
            "mitre_technique": "T1110.001",
            "mitre_tactic": "Credential Access",
            "attacker_ip": attacker_ip,
            "target_host": TARGET_HOST,
            "start_time": start.isoformat(),
            "compromise_time": success.isoformat(),
            "compromised_user": VALID_USER,
            "severity": "HIGH"
        })
    
    # Sort by timestamp
    logs.sort(key=lambda x: x[0])
    
    # Write auth.log
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    auth_log_path = os.path.join(OUTPUT_DIR, "auth.log")
    with open(auth_log_path, "w") as f:
        for ts, entry in logs:
            f.write(entry + "\n")
    
    # Write metadata
    metadata_path = os.path.join(OUTPUT_DIR, "ssh_bruteforce_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(attack_metadata, f, indent=2)
    
    print(f"[+] Generated {len(logs)} SSH log entries → {auth_log_path}")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return logs, attack_metadata


if __name__ == "__main__":
    generate_ssh_bruteforce_logs()
