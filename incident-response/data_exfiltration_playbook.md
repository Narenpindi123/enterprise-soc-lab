# Incident Response Playbook: Data Exfiltration

## Classification
- **Severity**: CRITICAL
- **MITRE ATT&CK**: T1048 (Exfiltration Over Alternative Protocol), T1567 (Exfiltration Over Web Service)
- **Priority**: P1

## Detection Indicators
- DNS tunneling: unusually long subdomain queries, high entropy domain names, excessive NXDOMAIN responses
- Large outbound data transfers to external IPs (>100MB to single destination)
- Unusual S3 bucket access patterns (GetObject on sensitive buckets from new IPs)
- HTTP/HTTPS uploads to known file sharing services or suspicious domains
- Proxy logs showing large POST requests to uncategorized domains

## Immediate Response (First 15 Minutes)

### 1. Validate the Alert
- [ ] Confirm the data transfer is not legitimate business activity
- [ ] Identify the source host and user account
- [ ] Determine the destination (IP, domain, cloud service)
- [ ] Estimate the volume of data transferred

### 2. Containment
- [ ] Block outbound communication to the exfiltration destination
- [ ] Isolate the source host from the network
- [ ] Disable the associated user account
- [ ] If cloud exfiltration: revoke IAM access keys immediately

### 3. Preserve Evidence
- [ ] Capture full packet capture (PCAP) from the host if available
- [ ] Export DNS query logs for the suspicious domains
- [ ] Preserve proxy logs and S3 access logs
- [ ] Snapshot the host's file system if possible

## Investigation (First 2 Hours)

### 4. Determine Exfiltration Method
- [ ] **DNS Tunneling**: Analyze query patterns, decode subdomain data, identify C2 domain
- [ ] **HTTP/HTTPS**: Review proxy logs for large uploads, check URL patterns
- [ ] **S3 Exfiltration**: Audit bucket access logs, identify accessed objects
- [ ] **Other**: Check for encrypted channels, steganography, or custom protocols

### 5. Data Impact Assessment
- [ ] Identify what data was accessed before exfiltration
- [ ] Determine classification level of exfiltrated data
- [ ] Check if PII, financial data, or trade secrets were involved
- [ ] Estimate total data volume exfiltrated

### 6. Root Cause Analysis
- [ ] Trace the attack chain backwards from the exfiltration point
- [ ] Identify initial access method (compromise vector)
- [ ] Map all systems the attacker accessed (lateral movement)
- [ ] Determine dwell time (how long the attacker had access)

## Remediation

### 7. Short-term
- [ ] Block all identified IOCs (IPs, domains, hashes) at perimeter
- [ ] Rotate all credentials for affected accounts
- [ ] Patch or remediate the initial access vulnerability
- [ ] Deploy enhanced monitoring on affected systems

### 8. Long-term
- [ ] Implement DLP (Data Loss Prevention) policies
- [ ] Deploy DNS monitoring for tunneling detection
- [ ] Restrict outbound traffic to approved destinations only
- [ ] Implement S3 bucket policies with IP restrictions
- [ ] Enable VPC Flow Logs if in cloud environment

## Legal & Compliance
- [ ] Notify legal team if PII or regulated data was exfiltrated
- [ ] Prepare breach notification if required by regulation (GDPR, HIPAA, etc.)
- [ ] Engage external forensics team if scope warrants it
- [ ] Document chain of custody for all evidence

## Post-Incident
- [ ] Complete detailed incident report with full timeline
- [ ] Update detection rules and threat intelligence
- [ ] Conduct tabletop exercise based on this incident
- [ ] Review and update data classification policies
