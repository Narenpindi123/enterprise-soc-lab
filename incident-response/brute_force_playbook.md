# Incident Response Playbook: Brute Force Attack

## Classification
- **Severity**: HIGH
- **MITRE ATT&CK**: T1110 (Brute Force)
- **Priority**: P2

## Detection Indicators
- Multiple failed authentication attempts (>10 in 5 minutes) from single source IP
- SSH Event: repeated `authentication failure` in auth.log
- Windows Event: Event ID 4625 (Failed Logon) with Logon Type 10 (RDP)
- Followed by a successful logon from same source IP (credential compromise)

## Immediate Response (First 15 Minutes)

### 1. Validate the Alert
- [ ] Confirm the alert is not a false positive (e.g., service account password rotation)
- [ ] Identify the source IP address and geolocate it
- [ ] Determine the targeted user accounts

### 2. Containment
- [ ] Block the attacking IP at the perimeter firewall
- [ ] If successful logon detected after brute force:
  - [ ] Disable the compromised account immediately
  - [ ] Kill all active sessions for the compromised account
  - [ ] Isolate the target host from the network

### 3. Preserve Evidence
- [ ] Export relevant log entries (auth.log, Windows Security events)
- [ ] Capture network flow data for the attacking IP
- [ ] Screenshot the alert details from the SOC dashboard

## Investigation (First Hour)

### 4. Scope Assessment
- [ ] Search for the attacking IP across all log sources
- [ ] Identify if multiple accounts were targeted
- [ ] Check if the attacking IP accessed any other services
- [ ] Determine if any lateral movement occurred after compromise

### 5. Credential Impact
- [ ] Identify which credentials were compromised
- [ ] Check if compromised credentials are reused on other systems
- [ ] Review recent access activity for compromised accounts

## Remediation

### 6. Short-term
- [ ] Force password reset for all compromised accounts
- [ ] Add source IP to threat intel blocklist
- [ ] Enable account lockout policies if not already in place
- [ ] Enable MFA for targeted accounts

### 7. Long-term
- [ ] Implement rate limiting on authentication endpoints
- [ ] Deploy fail2ban or similar automated blocking for SSH
- [ ] Review and harden RDP configuration (NLA, IP restriction)
- [ ] Update firewall rules to restrict SSH/RDP to known IPs

## Post-Incident
- [ ] Complete incident report with timeline
- [ ] Update detection rules based on lessons learned
- [ ] Brief the security team on findings
- [ ] Schedule follow-up review in 30 days
