#!/usr/bin/env python3
"""
Data Exfiltration Simulation
Generates DNS tunneling, HTTP exfiltration, and suspicious S3 access logs.
MITRE ATT&CK: T1048.001 - Exfil Over Symmetric Encrypted Non-C2,
               T1071.004 - Application Layer Protocol: DNS,
               T1537 - Transfer Data to Cloud Account
"""

import os
import json
import random
import base64
import string
from datetime import datetime, timedelta

NETWORK_OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "network")
CLOUD_OUTPUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "cloud")

INTERNAL_IPS = ["10.0.1.50", "10.0.1.51", "10.0.2.10"]
DNS_SERVER = "10.0.0.2"
PROXY_SERVER = "10.0.0.5"
ATTACKER_C2 = "198.51.100.23"
ATTACKER_DOMAIN = "cdn-update.evil-corp.xyz"

NORMAL_DOMAINS = [
    "google.com", "github.com", "amazonaws.com", "microsoft.com",
    "cloudflare.com", "stackoverflow.com", "ubuntu.com", "docker.com",
    "npmjs.org", "pypi.org", "slack.com", "zoom.us",
]


def generate_dns_log_entry(timestamp, src_ip, query_domain, query_type="A", response="NOERROR"):
    """Generate a DNS query log entry."""
    ts = timestamp.strftime("%d-%b-%Y %H:%M:%S.%f")[:-3]
    return f"{ts} queries: info: client @{hex(random.randint(0x1000, 0xFFFF))} {src_ip}#{random.randint(40000,65000)} ({query_domain}): query: {query_domain} IN {query_type} + ({DNS_SERVER})"


def generate_dns_tunneling_query():
    """Generate a DNS tunneling subdomain (encoded data in subdomain)."""
    # Simulate base32/hex encoded data chunks as subdomains
    chunk = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(40, 63)))
    seq = random.randint(0, 999)
    return f"{chunk}.{seq}.{ATTACKER_DOMAIN}"


def generate_proxy_log(timestamp, src_ip, method, url, status, bytes_sent, bytes_received, user_agent="Mozilla/5.0"):
    """Generate a proxy/web filter log entry."""
    ts = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    duration = random.randint(50, 5000)
    return f"{ts} {duration} {src_ip} TCP_{status}/{status} {bytes_received} {method} {url} - DIRECT/{ATTACKER_C2 if 'evil' in url or '198.51' in url else random.choice(['142.250.80.46', '185.199.108.133', '13.107.42.14'])} {user_agent}"


def generate_dns_exfiltration(base_time):
    """Generate DNS tunneling exfiltration logs."""
    logs = []
    
    # Normal DNS activity (baseline)
    for i in range(80):
        ts = base_time + timedelta(minutes=random.randint(0, 2880))
        src = random.choice(INTERNAL_IPS)
        domain = random.choice(NORMAL_DOMAINS)
        query_type = random.choice(["A", "AAAA", "CNAME"])
        logs.append((ts, generate_dns_log_entry(ts, src, domain, query_type)))
    
    # DNS tunneling attack
    attack_start = base_time + timedelta(hours=random.randint(8, 20))
    src_ip = "10.0.1.50"  # Compromised host
    
    # High volume of TXT queries to suspicious domain
    for i in range(200):
        ts = attack_start + timedelta(seconds=i * random.uniform(0.5, 3.0))
        tunnel_domain = generate_dns_tunneling_query()
        query_type = random.choice(["TXT", "CNAME", "A"])
        logs.append((ts, generate_dns_log_entry(ts, src_ip, tunnel_domain, query_type)))
    
    return logs, attack_start


def generate_http_exfiltration(base_time):
    """Generate HTTP-based data exfiltration via proxy logs."""
    logs = []
    
    # Normal web traffic
    normal_urls = [
        "http://github.com/api/v3/repos",
        "https://stackoverflow.com/questions",
        "https://docs.python.org/3/library",
        "https://registry.npmjs.org/express",
        "https://pypi.org/simple/requests/",
        "https://slack.com/api/chat.postMessage",
    ]
    
    for i in range(40):
        ts = base_time + timedelta(minutes=random.randint(0, 2880))
        src = random.choice(INTERNAL_IPS)
        url = random.choice(normal_urls)
        method = random.choice(["GET", "POST"])
        bytes_sent = random.randint(200, 2000)
        bytes_recv = random.randint(500, 50000)
        logs.append((ts, generate_proxy_log(ts, src, method, url, 200, bytes_sent, bytes_recv)))
    
    # HTTP exfiltration - large POST requests to external server
    attack_start = base_time + timedelta(hours=random.randint(10, 22))
    src_ip = "10.0.1.50"
    
    exfil_urls = [
        f"https://{ATTACKER_DOMAIN}/api/upload",
        f"https://{ATTACKER_DOMAIN}/api/sync",
        f"http://{ATTACKER_C2}/data",
        f"https://{ATTACKER_DOMAIN}/api/backup",
    ]
    
    for i in range(30):
        ts = attack_start + timedelta(minutes=i * random.randint(1, 5))
        url = random.choice(exfil_urls)
        bytes_sent = random.randint(500000, 5000000)  # Large uploads
        bytes_recv = random.randint(100, 500)
        logs.append((ts, generate_proxy_log(ts, src_ip, "POST", url, 200, bytes_sent, bytes_recv,
                                             "python-requests/2.31.0")))
    
    return logs, attack_start


def generate_s3_exfiltration(base_time):
    """Generate suspicious S3 access patterns."""
    events = []
    
    s3_buckets = [
        "corpsec-prod-data",
        "corpsec-hr-documents",
        "corpsec-financial-reports",
        "corpsec-customer-db-backups",
    ]
    
    sensitive_keys = [
        "hr/employees/salary_data_2026.csv",
        "finance/quarterly_reports/Q4_2025.xlsx",
        "customers/pii/customer_dump_full.sql.gz",
        "backups/database/prod_db_2026-02-17.tar.gz",
        "hr/employees/ssn_records.csv",
        "finance/tax/w2_forms_2025.zip",
    ]
    
    # Normal S3 access
    for i in range(15):
        ts = base_time + timedelta(minutes=random.randint(0, 2880))
        events.append((ts, {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "eventTime": ts.isoformat() + "Z",
            "sourceIPAddress": "10.0.1.50",
            "userAgent": "aws-cli/2.15.0",
            "requestParameters": {
                "bucketName": "corpsec-prod-data",
                "key": f"app/config/settings_{random.randint(1,5)}.json"
            },
            "responseElements": None,
            "additionalEventData": {
                "bytesTransferredOut": random.randint(1000, 50000)
            }
        }))
    
    # Suspicious S3 mass download (exfiltration)
    attack_start = base_time + timedelta(hours=random.randint(12, 24))
    
    for i, key in enumerate(sensitive_keys):
        for bucket in random.sample(s3_buckets, k=random.randint(1, 3)):
            ts = attack_start + timedelta(minutes=i * 2 + random.randint(0, 3))
            bytes_out = random.randint(5000000, 500000000)  # 5MB - 500MB
            events.append((ts, {
                "eventVersion": "1.08",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "eventTime": ts.isoformat() + "Z",
                "sourceIPAddress": "198.51.100.23",
                "userAgent": "aws-cli/2.15.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "dev-ops-svc",
                    "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
                },
                "requestParameters": {
                    "bucketName": bucket,
                    "key": key
                },
                "responseElements": None,
                "additionalEventData": {
                    "bytesTransferredOut": bytes_out
                }
            }))
    
    # ListBucket calls (reconnaissance before exfil)
    for bucket in s3_buckets:
        ts = attack_start - timedelta(minutes=random.randint(5, 30))
        events.append((ts, {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBucket",
            "eventTime": ts.isoformat() + "Z",
            "sourceIPAddress": "198.51.100.23",
            "userAgent": "aws-cli/2.15.0",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "dev-ops-svc",
                "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
            },
            "requestParameters": {
                "bucketName": bucket
            }
        }))
    
    return events, attack_start


def generate_data_exfiltration_logs(base_time=None):
    """Generate all data exfiltration logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    attack_metadata = []
    
    # DNS exfiltration
    dns_logs, dns_start = generate_dns_exfiltration(base_time)
    attack_metadata.append({
        "attack_type": "dns_tunneling_exfiltration",
        "mitre_technique": "T1071.004",
        "mitre_tactic": "Exfiltration",
        "source_ip": "10.0.1.50",
        "c2_domain": ATTACKER_DOMAIN,
        "start_time": dns_start.isoformat(),
        "query_count": 200,
        "severity": "HIGH"
    })
    
    # HTTP exfiltration
    http_logs, http_start = generate_http_exfiltration(base_time)
    attack_metadata.append({
        "attack_type": "http_data_exfiltration",
        "mitre_technique": "T1048.001",
        "mitre_tactic": "Exfiltration",
        "source_ip": "10.0.1.50",
        "c2_ip": ATTACKER_C2,
        "start_time": http_start.isoformat(),
        "estimated_data_exfiltrated": "~100MB",
        "severity": "CRITICAL"
    })
    
    # S3 exfiltration
    s3_events, s3_start = generate_s3_exfiltration(base_time)
    attack_metadata.append({
        "attack_type": "s3_data_exfiltration",
        "mitre_technique": "T1537",
        "mitre_tactic": "Exfiltration",
        "source_ip": ATTACKER_C2,
        "compromised_user": "dev-ops-svc",
        "start_time": s3_start.isoformat(),
        "sensitive_files_accessed": 6,
        "severity": "CRITICAL"
    })
    
    # Sort and write DNS logs
    dns_logs.sort(key=lambda x: x[0])
    os.makedirs(NETWORK_OUTPUT, exist_ok=True)
    dns_path = os.path.join(NETWORK_OUTPUT, "dns_queries.log")
    with open(dns_path, "w") as f:
        for ts, entry in dns_logs:
            f.write(entry + "\n")
    
    # Sort and write proxy logs
    http_logs.sort(key=lambda x: x[0])
    proxy_path = os.path.join(NETWORK_OUTPUT, "proxy_access.log")
    with open(proxy_path, "w") as f:
        for ts, entry in http_logs:
            f.write(entry + "\n")
    
    # Sort and write S3 events
    s3_events.sort(key=lambda x: x[0])
    os.makedirs(CLOUD_OUTPUT, exist_ok=True)
    s3_path = os.path.join(CLOUD_OUTPUT, "s3_access_events.json")
    with open(s3_path, "w") as f:
        json.dump([e[1] for e in s3_events], f, indent=2)
    
    # Write metadata
    metadata_path = os.path.join(NETWORK_OUTPUT, "exfiltration_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(attack_metadata, f, indent=2)
    
    print(f"[+] Generated {len(dns_logs)} DNS log entries → {dns_path}")
    print(f"[+] Generated {len(http_logs)} Proxy log entries → {proxy_path}")
    print(f"[+] Generated {len(s3_events)} S3 access events → {s3_path}")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return attack_metadata


if __name__ == "__main__":
    generate_data_exfiltration_logs()
