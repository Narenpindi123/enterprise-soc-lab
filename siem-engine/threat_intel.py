#!/usr/bin/env python3
"""
Threat Intelligence Module
IOC (Indicators of Compromise) database for log enrichment.
Matches against known-bad IPs, domains, and hashes.
"""

# Known malicious indicators
MALICIOUS_IPS = {
    "198.51.100.23": {
        "reputation": "malicious",
        "tags": ["brute_force", "c2", "data_exfil"],
        "source": "AlienVault OTX",
        "first_seen": "2025-11-15",
        "country": "RU",
        "asn": "AS12345 Evil Corp Hosting",
        "confidence": 95
    },
    "203.0.113.45": {
        "reputation": "malicious",
        "tags": ["brute_force", "scanner"],
        "source": "AlienVault OTX",
        "first_seen": "2025-12-01",
        "country": "CN",
        "asn": "AS67890 Shady Cloud VPS",
        "confidence": 90
    },
    "192.0.2.100": {
        "reputation": "suspicious",
        "tags": ["scanner", "recon"],
        "source": "AbuseIPDB",
        "first_seen": "2026-01-10",
        "country": "KR",
        "asn": "AS11111 Korea Telecom",
        "confidence": 75
    },
}

MALICIOUS_DOMAINS = {
    "cdn-update.evil-corp.xyz": {
        "reputation": "malicious",
        "tags": ["c2", "dns_tunneling", "malware"],
        "source": "VirusTotal",
        "first_seen": "2026-01-20",
        "registrar": "Namecheap Inc",
        "confidence": 98
    },
    "update-service.malware.top": {
        "reputation": "malicious",
        "tags": ["malware_distribution"],
        "source": "AlienVault OTX",
        "first_seen": "2025-09-05",
        "confidence": 92
    },
}

MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {
        "reputation": "malicious",
        "name": "beacon.exe",
        "family": "CobaltStrike",
        "source": "VirusTotal",
        "detection_rate": "58/72",
        "confidence": 99
    },
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4": {
        "reputation": "malicious",
        "name": "svc.exe",
        "family": "CustomRAT",
        "source": "Hybrid Analysis",
        "detection_rate": "45/72",
        "confidence": 88
    },
}

# Known internal/safe ranges
INTERNAL_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


def is_internal_ip(ip):
    """Check if an IP is in internal ranges (simple check)."""
    return (ip.startswith("10.") or 
            ip.startswith("172.16.") or ip.startswith("172.17.") or
            ip.startswith("172.18.") or ip.startswith("172.19.") or
            ip.startswith("172.2") or ip.startswith("172.3") or
            ip.startswith("192.168."))


def lookup_ip(ip):
    """Look up an IP address in the threat intel database."""
    if ip in MALICIOUS_IPS:
        return {
            "found": True,
            "indicator": ip,
            "type": "ip",
            **MALICIOUS_IPS[ip]
        }
    return {"found": False, "indicator": ip, "type": "ip"}


def lookup_domain(domain):
    """Look up a domain in the threat intel database."""
    # Check exact match and parent domains
    parts = domain.split(".")
    for i in range(len(parts)):
        check_domain = ".".join(parts[i:])
        if check_domain in MALICIOUS_DOMAINS:
            return {
                "found": True,
                "indicator": check_domain,
                "matched_query": domain,
                "type": "domain",
                **MALICIOUS_DOMAINS[check_domain]
            }
    return {"found": False, "indicator": domain, "type": "domain"}


def lookup_hash(hash_value):
    """Look up a file hash in the threat intel database."""
    if hash_value in MALICIOUS_HASHES:
        return {
            "found": True,
            "indicator": hash_value,
            "type": "hash",
            **MALICIOUS_HASHES[hash_value]
        }
    return {"found": False, "indicator": hash_value, "type": "hash"}


def enrich_event(event):
    """Enrich a normalized event with threat intelligence."""
    enrichments = []
    details = event.get("details", {})
    
    # Check source IP
    source_ip = details.get("source_ip", "")
    if source_ip and source_ip != "unknown":
        ip_result = lookup_ip(source_ip)
        if ip_result["found"]:
            enrichments.append(ip_result)
    
    # Check domains
    domain = details.get("query_domain", "")
    if domain and domain != "unknown":
        domain_result = lookup_domain(domain)
        if domain_result["found"]:
            enrichments.append(domain_result)
    
    # Check URLs for domains
    url = details.get("url", "")
    if url:
        import re
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            url_domain = domain_match.group(1)
            domain_result = lookup_domain(url_domain)
            if domain_result["found"]:
                enrichments.append(domain_result)
    
    if enrichments:
        event["threat_intel"] = enrichments
        # Elevate severity if threat intel match
        current_severity = event.get("severity", "LOW")
        if current_severity in ["LOW", "MEDIUM"]:
            event["severity"] = "HIGH"
    
    return event


if __name__ == "__main__":
    print("Threat Intelligence Database Summary:")
    print(f"  Malicious IPs: {len(MALICIOUS_IPS)}")
    print(f"  Malicious Domains: {len(MALICIOUS_DOMAINS)}")
    print(f"  Malicious Hashes: {len(MALICIOUS_HASHES)}")
    print()
    print("Sample lookups:")
    print(f"  IP 198.51.100.23: {lookup_ip('198.51.100.23')}")
    print(f"  Domain cdn-update.evil-corp.xyz: {lookup_domain('cdn-update.evil-corp.xyz')}")
