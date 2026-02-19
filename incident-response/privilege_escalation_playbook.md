# Incident Response Playbook: Privilege Escalation

## Classification
- **Severity**: HIGH / CRITICAL
- **MITRE ATT&CK**: T1548 (Abuse Elevation Control), T1059 (Command and Scripting Interpreter)
- **Priority**: P1

## Detection Indicators
- Unauthorized sudo usage or sudo abuse on Linux systems
- PowerShell execution with encoded commands (-enc, -EncodedCommand)
- Credential dumping tools detected (Mimikatz, procdump targeting lsass)
- Windows Event ID 4672 (Special privileges assigned to new logon) for unexpected users
- Rapid sequence: failed sudo → successful sudo → suspicious command execution

## Immediate Response (First 15 Minutes)

### 1. Validate the Alert
- [ ] Confirm the escalation was not an authorized administrative action
- [ ] Identify the user account and source host
- [ ] Determine the escalation method (sudo abuse, exploit, credential theft)
- [ ] Check if the account should have elevated privileges

### 2. Containment
- [ ] Lock the user account immediately
- [ ] Isolate the affected host
- [ ] If domain credentials are compromised: reset the KRBTGT account
- [ ] Disable PowerShell remoting on affected systems

### 3. Preserve Evidence
- [ ] Capture auth.log / Windows Security event logs
- [ ] Record the escalation commands and their outputs
- [ ] Preserve any downloaded tools or scripts

## Investigation (First Hour)

### 4. Scope Assessment
- [ ] Determine what commands were run with elevated privileges
- [ ] Check for new user accounts, cron jobs, or services created
- [ ] Search for persistence mechanisms installed after escalation
- [ ] Identify if credentials were dumped or tokens stolen

### 5. Lateral Movement Check
- [ ] Search for the compromised account's activity across all systems
- [ ] Check for new SSH keys, RDP sessions, or SMB connections
- [ ] Review network connections from the affected host

## Remediation

### 6. Short-term
- [ ] Rotate credentials for the affected account and any accessed systems
- [ ] Remove any unauthorized persistence mechanisms
- [ ] Patch the escalation vulnerability if applicable
- [ ] Revoke any tokens or sessions from the compromised account

### 7. Long-term
- [ ] Implement principle of least privilege for all accounts
- [ ] Deploy application whitelisting to prevent unauthorized tool execution
- [ ] Restrict PowerShell execution policies (Constrained Language Mode)
- [ ] Implement sudo logging and alerting
- [ ] Deploy LAPS (Local Administrator Password Solution) on Windows

## Post-Incident
- [ ] Complete incident report with privilege escalation chain documented
- [ ] Update detection rules for the specific escalation technique
- [ ] Review privilege assignment policies organization-wide
- [ ] Conduct access review for all privileged accounts
