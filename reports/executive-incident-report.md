# Executive Incident Report

**Classification:** CONFIDENTIAL  
**Report ID:** IR-2026-0217-001  
**Date:** February 19, 2026  
**Prepared By:** Naren Pindi, SOC Analyst  
**Status:** Resolved

---

## 1. Incident Summary

| Field | Detail |
|-------|--------|
| **Incident Type** | Multi-stage intrusion — Brute Force → Privilege Escalation → Data Exfiltration |
| **Detection Time** | Feb 17, 2026 05:21 UTC |
| **Severity** | **CRITICAL** |
| **Affected Systems** | `prod-web-01` (Linux), `WS-FIN-PC04` (Windows), AWS Account `471092389142` |
| **Attacker IPs** | `198.51.100.23`, `203.0.113.45`, `192.0.2.100` |
| **MITRE ATT&CK Tactics** | Initial Access, Credential Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Command & Control, Exfiltration |
| **Business Impact** | Potential exposure of customer data and cloud infrastructure credentials |

---

## 2. Attack Timeline

```
05:21 UTC ─── Windows Brute Force (198.51.100.23 → WS-FIN-PC04)
              [T1110.001 - Brute Force: Password Guessing]
              200+ failed logon attempts (Event ID 4625)

05:30 UTC ─── SSH Brute Force (198.51.100.23 → prod-web-01)
              [T1110.001] 150+ failed attempts against 'deploy' account

06:23 UTC ─── SSH Brute Force (192.0.2.100 → prod-web-01)
              [T1110.001] Second attacker IP begins coordinated attack

06:45 UTC ─── SSH Brute Force (203.0.113.45 → prod-web-01)
              [T1110.001] Third attacker IP — distributed attack pattern

08:00 UTC ─── Account Compromise Confirmed
              Successful login as 'deploy' user (compromised credentials)

08:15 UTC ─── Privilege Escalation via Sudo Abuse
              [T1548.003] Attacker escalates to root via sudo misconfiguration

09:30 UTC ─── Persistence Mechanisms Installed
              [T1053.003] Malicious cron job planted
              [T1543.002] Backdoor systemd service created
              [T1547.001] Windows Registry Run key added

12:00 UTC ─── Cloud Infrastructure Compromised
              [T1078.004] AWS access keys extracted and used
              [T1098.001] New IAM credentials created for persistence
              [T1562.007] Cloud firewall rules modified

14:00 UTC ─── Data Exfiltration Begins
              [T1071.004] DNS tunneling to attacker-controlled domain
              [T1537] Sensitive data copied to external S3 bucket
```

---

## 3. Root Cause Analysis

| Factor | Finding |
|--------|---------|
| **Initial Vector** | SSH and RDP services exposed to internet without rate limiting |
| **Credential Weakness** | Service account `deploy` had a weak password susceptible to brute force |
| **Privilege Escalation** | Sudo configuration allowed password-less escalation for the `deploy` user |
| **Cloud Security Gap** | AWS access keys stored in plaintext on the compromised server |
| **Exfiltration Path** | No DLP controls on DNS or outbound S3 traffic |

---

## 4. Business Impact Assessment

| Impact Area | Assessment |
|-------------|------------|
| **Data at Risk** | Customer records, database credentials, cloud infrastructure keys |
| **Systems Compromised** | 2 servers (Linux + Windows) + 1 AWS account |
| **Operational Impact** | Potential service disruption during remediation |
| **Regulatory Exposure** | May require breach notification if customer PII confirmed exfiltrated |
| **Estimated Cost** | $50,000 – $150,000 (incident response, forensics, remediation, notification) |

---

## 5. Remediation Actions Taken

### Immediate (0–4 hours)
- [x] Isolated compromised hosts from network
- [x] Revoked compromised AWS access keys
- [x] Reset credentials for `deploy` and `svc_backup` accounts
- [x] Blocked attacker IPs at perimeter firewall
- [x] Disabled malicious cron jobs and systemd services

### Short-Term (1–7 days)
- [x] Full forensic imaging of compromised systems
- [x] Audit of all IAM users, roles, and policies
- [x] Rotate all service account credentials
- [x] Implement MFA on all privileged accounts
- [x] Deploy rate limiting on SSH and RDP endpoints

### Long-Term (30 days)
- [ ] Implement network segmentation between DMZ and internal zones
- [ ] Deploy EDR solution on all endpoints
- [ ] Enable AWS GuardDuty and CloudTrail alerting
- [ ] Implement DLP controls for DNS and S3 exfiltration detection
- [ ] Conduct red team exercise to validate improvements

---

## 6. Strategic Recommendations

1. **Enforce Zero Trust Access** — Replace password-based SSH with certificate authentication; require MFA for all remote access
2. **Implement Cloud Security Posture Management (CSPM)** — Continuously monitor IAM misconfigurations and exposed credentials
3. **Deploy DLP & Network Monitoring** — Monitor DNS query patterns and S3 data transfers for anomalous volumes
4. **Harden Service Accounts** — Apply least privilege, rotate credentials every 90 days, remove sudo access where unnecessary
5. **SOC Process Improvements** — Implement 24/7 monitoring with automated alert escalation for brute force and privilege escalation events

---

## 7. Detection Coverage Summary

| MITRE Tactic | Techniques Detected | Detection Confidence |
|--------------|--------------------|--------------------|
| Initial Access | T1078.004 | HIGH |
| Credential Access | T1110.001 | HIGH |
| Execution | T1059.001 | HIGH |
| Persistence | T1053.003, T1543.002, T1547.001, T1098.001, T1136.003 | HIGH |
| Privilege Escalation | T1548.003 | HIGH |
| Defense Evasion | T1562.001, T1562.007 | MEDIUM |
| Lateral Movement | T1550.001 | MEDIUM |
| Command & Control | T1071.004, T1071 | HIGH |
| Exfiltration | T1537 | HIGH |

**24 of 25 detection rules triggered** — 96% detection efficacy.

---

*This report was generated as part of the Enterprise SOC Lab project to demonstrate executive-level incident reporting capabilities.*
