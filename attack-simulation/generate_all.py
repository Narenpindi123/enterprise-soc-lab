#!/usr/bin/env python3
"""
Master Attack Simulation Generator
Runs all attack simulation scripts in chronological order to generate
a unified 48-hour attack timeline.
"""

import os
import sys
import json
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_bruteforce import generate_ssh_bruteforce_logs
from windows_logon_failures import generate_windows_logon_logs
from privilege_escalation import generate_privilege_escalation_logs
from persistence import generate_persistence_logs
from cloud_abuse import generate_cloud_abuse_logs
from data_exfiltration import generate_data_exfiltration_logs


def main():
    """Generate all attack simulation logs with a unified timeline."""
    print("=" * 70)
    print("  Enterprise SOC Lab - Attack Simulation Generator")
    print("  Generating 48-hour attack timeline...")
    print("=" * 70)
    print()
    
    # Base time for all simulations (synchronized timeline)
    base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    # Phase 1: Initial Access (SSH + Windows brute force)
    print("[Phase 1] Initial Access - Brute Force Attacks")
    print("-" * 50)
    ssh_logs, ssh_meta = generate_ssh_bruteforce_logs(base_time)
    win_events, win_meta = generate_windows_logon_logs(base_time)
    print()
    
    # Phase 2: Privilege Escalation
    print("[Phase 2] Privilege Escalation - Sudo Abuse & PowerShell")
    print("-" * 50)
    linux_privesc, win_privesc, privesc_meta = generate_privilege_escalation_logs(base_time)
    print()
    
    # Phase 3: Persistence
    print("[Phase 3] Persistence - Cron Jobs, Systemd, Registry")
    print("-" * 50)
    persist_meta = generate_persistence_logs(base_time)
    print()
    
    # Phase 4: Cloud Abuse
    print("[Phase 4] Cloud Abuse - AWS IAM Escalation")
    print("-" * 50)
    cloud_events, cloud_meta = generate_cloud_abuse_logs(base_time)
    print()
    
    # Phase 5: Data Exfiltration
    print("[Phase 5] Data Exfiltration - DNS Tunneling, HTTP, S3")
    print("-" * 50)
    exfil_meta = generate_data_exfiltration_logs(base_time)
    print()
    
    # Collect all attack metadata
    all_metadata = []
    all_metadata.extend(ssh_meta)
    all_metadata.extend(win_meta)
    all_metadata.extend(privesc_meta)
    all_metadata.extend(persist_meta)
    all_metadata.extend(cloud_meta)
    all_metadata.extend(exfil_meta)
    
    # Write unified metadata
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    unified_path = os.path.join(output_dir, "attack_timeline.json")
    with open(unified_path, "w") as f:
        json.dump({
            "simulation_start": base_time.isoformat(),
            "simulation_duration_hours": 48,
            "total_attack_scenarios": len(all_metadata),
            "attacks": all_metadata
        }, f, indent=2)
    
    print("=" * 70)
    print(f"  ✅ Attack simulation complete!")
    print(f"  📊 Total attack scenarios: {len(all_metadata)}")
    print(f"  📁 Unified timeline → {unified_path}")
    print(f"  📂 Log files → {output_dir}/")
    print("=" * 70)
    print()
    print("  Next step: Run the SIEM engine to detect these attacks:")
    print("  $ python3 siem-engine/alert_engine.py")
    print()


if __name__ == "__main__":
    main()
