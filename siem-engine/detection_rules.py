#!/usr/bin/env python3
"""
Detection Rules Engine
Contains 25+ detection rules mapped to MITRE ATT&CK techniques.
Each rule defines conditions, severity, and response recommendations.
"""


DETECTION_RULES = [
    # ==========================================
    # INITIAL ACCESS & CREDENTIAL ACCESS
    # ==========================================
    {
        "rule_id": "DET-001",
        "name": "SSH Brute Force Detected",
        "description": "Multiple failed SSH login attempts from the same source IP within a short timeframe",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "mitre_name": "Brute Force: Password Guessing",
        "severity": "HIGH",
        "source": "linux_auth",
        "conditions": {
            "event_type": "authentication_failure",
            "threshold": 10,
            "time_window_minutes": 10,
            "group_by": "details.source_ip"
        },
        "response": "Block source IP at firewall. Rotate credentials for targeted accounts."
    },
    {
        "rule_id": "DET-002",
        "name": "Windows RDP Brute Force Detected",
        "description": "Multiple failed Windows logon attempts (Event 4625) from the same source IP",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "mitre_name": "Brute Force: Password Guessing",
        "severity": "HIGH",
        "source": "windows_security",
        "conditions": {
            "event_type": "authentication_failure",
            "threshold": 15,
            "time_window_minutes": 10,
            "group_by": "details.source_ip"
        },
        "response": "Block source IP. Enable account lockout policies. Review RDP exposure."
    },
    {
        "rule_id": "DET-003",
        "name": "Successful Login After Brute Force",
        "description": "Successful authentication from an IP that previously had multiple failed attempts",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "mitre_name": "Brute Force: Password Guessing",
        "severity": "CRITICAL",
        "source": ["linux_auth", "windows_security"],
        "conditions": {
            "event_type": "authentication_success",
            "preceding_failures": 5,
            "match_field": "details.source_ip"
        },
        "response": "IMMEDIATE: Disable compromised account. Isolate host. Begin IR investigation."
    },
    {
        "rule_id": "DET-004",
        "name": "Login from External/Unknown IP",
        "description": "Successful login from an IP outside known internal ranges",
        "mitre_technique": "T1078",
        "mitre_tactic": "Initial Access",
        "mitre_name": "Valid Accounts",
        "severity": "MEDIUM",
        "source": ["linux_auth", "windows_security"],
        "conditions": {
            "event_type": "authentication_success",
            "ip_not_in": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        },
        "response": "Verify if the login is authorized. Check VPN logs for context."
    },
    
    # ==========================================
    # PRIVILEGE ESCALATION
    # ==========================================
    {
        "rule_id": "DET-005",
        "name": "Unauthorized Sudo Attempt",
        "description": "User not in sudoers file attempted to execute command as root",
        "mitre_technique": "T1548.003",
        "mitre_tactic": "Privilege Escalation",
        "mitre_name": "Sudo and Sudo Caching",
        "severity": "HIGH",
        "source": "linux_auth",
        "conditions": {
            "event_type": "privilege_escalation",
            "detail_match": {"action": "sudo_denied"}
        },
        "response": "Investigate the user account. Check for lateral movement evidence."
    },
    {
        "rule_id": "DET-006",
        "name": "Suspicious Sudo Command Execution",
        "description": "Sudo used to execute high-risk commands (shell spawn, password change, user creation)",
        "mitre_technique": "T1548.003",
        "mitre_tactic": "Privilege Escalation",
        "mitre_name": "Sudo and Sudo Caching",
        "severity": "CRITICAL",
        "source": "linux_auth",
        "conditions": {
            "event_type": "privilege_escalation",
            "command_contains": ["/bin/bash", "/bin/sh", "passwd", "useradd", "usermod", "chmod 4755", "wget", "curl.*|.*bash", "python.*pty.spawn"]
        },
        "response": "IMMEDIATE: Isolate host. Review all commands executed by this user."
    },
    {
        "rule_id": "DET-007",
        "name": "Encoded PowerShell Execution",
        "description": "PowerShell executed with encoded command (-enc flag)",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "mitre_name": "Command and Scripting Interpreter: PowerShell",
        "severity": "CRITICAL",
        "source": "windows_security",
        "conditions": {
            "event_type": "process_creation",
            "command_contains": ["-enc", "-EncodedCommand", "FromBase64String"]
        },
        "response": "IMMEDIATE: Decode the command. Isolate endpoint. Check for C2 callbacks."
    },
    {
        "rule_id": "DET-008",
        "name": "PowerShell Download Cradle",
        "description": "PowerShell used to download and execute remote scripts",
        "mitre_technique": "T1059.001",
        "mitre_tactic": "Execution",
        "mitre_name": "Command and Scripting Interpreter: PowerShell",
        "severity": "CRITICAL",
        "source": "windows_security",
        "conditions": {
            "event_type": "process_creation",
            "command_contains": ["DownloadString", "DownloadFile", "Invoke-WebRequest", "wget", "curl", "Net.WebClient"]
        },
        "response": "Block the download URL. Isolate endpoint. Scan for payloads."
    },
    {
        "rule_id": "DET-009",
        "name": "Defense Evasion via PowerShell",
        "description": "PowerShell used to disable security controls (Windows Defender, firewall)",
        "mitre_technique": "T1562.001",
        "mitre_tactic": "Defense Evasion",
        "mitre_name": "Impair Defenses: Disable or Modify Tools",
        "severity": "CRITICAL",
        "source": "windows_security",
        "conditions": {
            "event_type": "process_creation",
            "command_contains": ["Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring", "advfirewall.*off"]
        },
        "response": "IMMEDIATE: Re-enable security tools. Isolate endpoint. Full forensic analysis."
    },
    {
        "rule_id": "DET-010",
        "name": "Credential Dumping Attempt",
        "description": "Mimikatz or similar credential dumping tool execution detected",
        "mitre_technique": "T1003.001",
        "mitre_tactic": "Credential Access",
        "mitre_name": "OS Credential Dumping: LSASS Memory",
        "severity": "CRITICAL",
        "source": "windows_security",
        "conditions": {
            "event_type": "process_creation",
            "command_contains": ["Invoke-Mimikatz", "sekurlsa", "lsadump", "kerberos::list"]
        },
        "response": "IMMEDIATE: Isolate host. Rotate ALL domain credentials. Check for lateral movement."
    },
    
    # ==========================================
    # PERSISTENCE
    # ==========================================
    {
        "rule_id": "DET-011",
        "name": "Suspicious Cron Job Creation",
        "description": "New cron job created with suspicious command (reverse shell, download)",
        "mitre_technique": "T1053.003",
        "mitre_tactic": "Persistence",
        "mitre_name": "Scheduled Task/Job: Cron",
        "severity": "HIGH",
        "source": "linux_auth",
        "conditions": {
            "event_type": ["scheduled_task", "scheduled_task_modified"],
            "command_contains": ["/dev/tcp", "bash -i", "curl.*|.*bash", "wget.*|.*sh", ".hidden"]
        },
        "response": "Review and remove malicious cron entries. Investigate compromised user."
    },
    {
        "rule_id": "DET-012",
        "name": "Suspicious Systemd Service Created",
        "description": "New systemd service installed, potential persistence mechanism",
        "mitre_technique": "T1543.002",
        "mitre_tactic": "Persistence",
        "mitre_name": "Create or Modify System Process: Systemd Service",
        "severity": "HIGH",
        "source": "linux_auth",
        "conditions": {
            "event_type": "service_activity",
            "detail_match": {"action": "systemd_activity"},
            "message_contains": ["Created slice", "Starting", "Started"]
        },
        "response": "Review service definition. Check for suspicious ExecStart commands."
    },
    {
        "rule_id": "DET-013",
        "name": "Registry Run Key Modification",
        "description": "Windows Registry Run/RunOnce key modified for persistence",
        "mitre_technique": "T1547.001",
        "mitre_tactic": "Persistence",
        "mitre_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "severity": "HIGH",
        "source": "windows_sysmon",
        "conditions": {
            "event_type": "registry_modification",
            "target_contains": ["CurrentVersion\\Run", "CurrentVersion\\RunOnce"]
        },
        "response": "Review the registry value. Remove unauthorized entries. Scan the binary."
    },
    
    # ==========================================
    # CLOUD ABUSE (AWS)
    # ==========================================
    {
        "rule_id": "DET-014",
        "name": "AWS API Call from Anomalous Region",
        "description": "AWS API calls originating from an unusual geographic region",
        "mitre_technique": "T1078.004",
        "mitre_tactic": "Initial Access",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "region_not_in": ["us-east-1", "us-west-2"]
        },
        "response": "Verify the API calls are authorized. Rotate access keys if unauthorized."
    },
    {
        "rule_id": "DET-015",
        "name": "AWS IAM User Created",
        "description": "New IAM user created, potential persistence via cloud accounts",
        "mitre_technique": "T1136.003",
        "mitre_tactic": "Persistence",
        "mitre_name": "Create Account: Cloud Account",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "CreateUser"}
        },
        "response": "Verify user creation was authorized. Check for additional escalation."
    },
    {
        "rule_id": "DET-016",
        "name": "AWS IAM Policy Escalation",
        "description": "AdministratorAccess or high-privilege policy attached to a user",
        "mitre_technique": "T1098.001",
        "mitre_tactic": "Persistence",
        "mitre_name": "Account Manipulation: Additional Cloud Credentials",
        "severity": "CRITICAL",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "AttachUserPolicy"},
            "param_contains": "AdministratorAccess"
        },
        "response": "IMMEDIATE: Detach the policy. Investigate who made the change. Rotate keys."
    },
    {
        "rule_id": "DET-017",
        "name": "AWS Access Key Created",
        "description": "New access key created for an IAM user",
        "mitre_technique": "T1098.001",
        "mitre_tactic": "Persistence",
        "mitre_name": "Account Manipulation: Additional Cloud Credentials",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "CreateAccessKey"}
        },
        "response": "Verify key creation was authorized. If not, disable the new key immediately."
    },
    {
        "rule_id": "DET-018",
        "name": "AWS Console Login Without MFA",
        "description": "Console login detected without multi-factor authentication",
        "mitre_technique": "T1078.004",
        "mitre_tactic": "Initial Access",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "ConsoleLogin"},
            "no_mfa": True
        },
        "response": "Enforce MFA for all console access. Investigate the login context."
    },
    {
        "rule_id": "DET-019",
        "name": "AWS Security Group Opened to World",
        "description": "Security group rule allows inbound traffic from 0.0.0.0/0",
        "mitre_technique": "T1562.007",
        "mitre_tactic": "Defense Evasion",
        "mitre_name": "Impair Defenses: Disable or Modify Cloud Firewall",
        "severity": "CRITICAL",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "AuthorizeSecurityGroupIngress"},
            "param_contains": "0.0.0.0/0"
        },
        "response": "IMMEDIATE: Revoke the rule. Review all security groups for similar misconfigurations."
    },
    {
        "rule_id": "DET-020",
        "name": "AWS Secrets Manager Access",
        "description": "Sensitive secret value retrieved from Secrets Manager",
        "mitre_technique": "T1552.005",
        "mitre_tactic": "Credential Access",
        "mitre_name": "Unsecured Credentials: Cloud Instance Metadata API",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "GetSecretValue"}
        },
        "response": "Verify secret access was authorized. Rotate the secret if compromised."
    },
    {
        "rule_id": "DET-021",
        "name": "AWS Assume Role from Unusual Source",
        "description": "AssumeRole API call from an unusual IP or with unusual session name",
        "mitre_technique": "T1550.001",
        "mitre_tactic": "Lateral Movement",
        "mitre_name": "Use Alternate Authentication Material: Application Access Token",
        "severity": "HIGH",
        "source": "aws_cloudtrail",
        "conditions": {
            "event_type": "cloud_api_call",
            "detail_match": {"event_name": "AssumeRole"}
        },
        "response": "Review role trust policies. Verify the session is legitimate."
    },
    
    # ==========================================
    # DATA EXFILTRATION
    # ==========================================
    {
        "rule_id": "DET-022",
        "name": "DNS Tunneling Detected",
        "description": "High volume of DNS queries with unusually long subdomains to a single domain",
        "mitre_technique": "T1071.004",
        "mitre_tactic": "Command and Control",
        "mitre_name": "Application Layer Protocol: DNS",
        "severity": "CRITICAL",
        "source": "dns",
        "conditions": {
            "event_type": "dns_query",
            "detail_match": {"suspicious": True, "reason": "unusually_long_subdomain"},
            "threshold": 20,
            "time_window_minutes": 30,
            "group_by": "details.source_ip"
        },
        "response": "Block the C2 domain. Isolate the source host. Analyze DNS payloads."
    },
    {
        "rule_id": "DET-023",
        "name": "Large Outbound HTTP Data Transfer",
        "description": "HTTP POST requests with unusually large payloads to external destinations",
        "mitre_technique": "T1048.001",
        "mitre_tactic": "Exfiltration",
        "mitre_name": "Exfiltration Over Alternative Protocol",
        "severity": "HIGH",
        "source": "proxy",
        "conditions": {
            "event_type": "web_request",
            "detail_match": {"suspicious": True, "reason": "large_outbound_data_transfer"}
        },
        "response": "Block the destination. Investigate what data was transferred."
    },
    {
        "rule_id": "DET-024",
        "name": "Suspicious S3 Bulk Data Access",
        "description": "Large volume of S3 GetObject requests for sensitive files from external IP",
        "mitre_technique": "T1537",
        "mitre_tactic": "Exfiltration",
        "mitre_name": "Transfer Data to Cloud Account",
        "severity": "CRITICAL",
        "source": "aws_s3",
        "conditions": {
            "event_type": "s3_access",
            "detail_match": {"suspicious": True}
        },
        "response": "Revoke access credentials. Enable S3 bucket versioning. Review bucket policies."
    },
    {
        "rule_id": "DET-025",
        "name": "Connection to Known Malicious IP",
        "description": "Network connection to a known threat intelligence indicator",
        "mitre_technique": "T1071",
        "mitre_tactic": "Command and Control",
        "mitre_name": "Application Layer Protocol",
        "severity": "HIGH",
        "source": ["proxy", "dns"],
        "conditions": {
            "ioc_match": True
        },
        "response": "Block the indicator. Isolate affected hosts. Run full malware scan."
    },
]


def get_rule_by_id(rule_id):
    """Get a detection rule by its ID."""
    for rule in DETECTION_RULES:
        if rule["rule_id"] == rule_id:
            return rule
    return None


def get_rules_by_tactic(tactic):
    """Get all detection rules for a MITRE ATT&CK tactic."""
    return [r for r in DETECTION_RULES if r["mitre_tactic"] == tactic]


def get_rules_by_severity(severity):
    """Get all detection rules at a given severity level."""
    return [r for r in DETECTION_RULES if r["severity"] == severity]


if __name__ == "__main__":
    print(f"Total detection rules: {len(DETECTION_RULES)}")
    print()
    
    tactics = {}
    for rule in DETECTION_RULES:
        tactic = rule["mitre_tactic"]
        tactics[tactic] = tactics.get(tactic, 0) + 1
    
    print("Rules by MITRE ATT&CK Tactic:")
    for tactic, count in sorted(tactics.items()):
        print(f"  {tactic}: {count}")
    
    severities = {}
    for rule in DETECTION_RULES:
        sev = rule["severity"]
        severities[sev] = severities.get(sev, 0) + 1
    
    print()
    print("Rules by Severity:")
    for sev, count in sorted(severities.items()):
        print(f"  {sev}: {count}")
