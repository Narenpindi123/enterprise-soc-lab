#!/usr/bin/env python3
"""
AWS Cloud Abuse Simulation
Generates AWS CloudTrail events for IAM privilege escalation and compromised access key abuse.
MITRE ATT&CK: T1078.004 - Cloud Accounts, T1098.001 - Additional Cloud Credentials
"""

import os
import json
import random
import uuid
from datetime import datetime, timedelta

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "cloud")

# AWS account details
AWS_ACCOUNT_ID = "123456789012"
AWS_REGION_LEGIT = "us-east-1"
AWS_REGION_ANOMALOUS = "eu-west-1"

# Legitimate IAM user
LEGIT_USER = "dev-ops-svc"
LEGIT_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
LEGIT_SOURCE_IP = "10.0.1.50"

# Attacker details
ATTACKER_IP = "198.51.100.23"
COMPROMISED_KEY = "AKIAIOSFODNN7EXAMPLE"  # Same key, different source

# Normal API calls
NORMAL_ACTIONS = [
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("s3.amazonaws.com", "GetBucketLocation"),
    ("sts.amazonaws.com", "GetCallerIdentity"),
    ("logs.amazonaws.com", "DescribeLogGroups"),
    ("cloudwatch.amazonaws.com", "DescribeAlarms"),
    ("elasticloadbalancing.amazonaws.com", "DescribeLoadBalancers"),
]

# Suspicious/Malicious API calls (IAM escalation)
MALICIOUS_ACTIONS = [
    ("iam.amazonaws.com", "CreateAccessKey", {"UserName": "dev-ops-svc"}),
    ("iam.amazonaws.com", "ListUsers", {}),
    ("iam.amazonaws.com", "ListAttachedUserPolicies", {"UserName": "dev-ops-svc"}),
    ("iam.amazonaws.com", "AttachUserPolicy", {"UserName": "dev-ops-svc", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    ("iam.amazonaws.com", "CreateUser", {"UserName": "svc-cloudops"}),
    ("iam.amazonaws.com", "CreateLoginProfile", {"UserName": "svc-cloudops"}),
    ("iam.amazonaws.com", "AttachUserPolicy", {"UserName": "svc-cloudops", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
    ("iam.amazonaws.com", "CreateAccessKey", {"UserName": "svc-cloudops"}),
    ("sts.amazonaws.com", "AssumeRole", {"RoleArn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/AdminRole", "RoleSessionName": "maintenance"}),
    ("ec2.amazonaws.com", "DescribeInstances", {}),
    ("ec2.amazonaws.com", "CreateSecurityGroup", {"GroupName": "debug-sg", "Description": "Temp debug"}),
    ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", {"GroupName": "debug-sg", "IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "CidrIp": "0.0.0.0/0"}),
    ("lambda.amazonaws.com", "ListFunctions", {}),
    ("secretsmanager.amazonaws.com", "ListSecrets", {}),
    ("secretsmanager.amazonaws.com", "GetSecretValue", {"SecretId": "prod/database/credentials"}),
]

CONSOLE_LOGIN_ACTIONS = [
    ("signin.amazonaws.com", "ConsoleLogin"),
]


def generate_cloudtrail_event(timestamp, source_ip, user_name, access_key, event_source, event_name,
                               request_params=None, response_code=200, region=None, error_code=None):
    """Generate a single CloudTrail event."""
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDAEXAMPLE{random.randint(10000,99999)}",
            "arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user_name}",
            "accountId": AWS_ACCOUNT_ID,
            "accessKeyId": access_key,
            "userName": user_name
        },
        "eventTime": timestamp.isoformat() + "Z",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region or AWS_REGION_LEGIT,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0-91-generic",
        "requestParameters": request_params or {},
        "responseElements": None if response_code != 200 else {"_return": True},
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": event_name.startswith(("Describe", "List", "Get")),
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": AWS_ACCOUNT_ID
    }
    
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = f"User: arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user_name} is not authorized to perform: {event_name}"
    
    return event


def generate_cloud_abuse_logs(base_time=None):
    """Generate all AWS CloudTrail abuse logs."""
    if base_time is None:
        base_time = datetime(2026, 2, 17, 0, 0, 0)
    
    events = []
    attack_metadata = []
    
    # === Legitimate API activity (baseline) ===
    for i in range(30):
        ts = base_time + timedelta(minutes=random.randint(0, 2880))
        action = random.choice(NORMAL_ACTIONS)
        events.append((ts, generate_cloudtrail_event(
            ts, LEGIT_SOURCE_IP, LEGIT_USER, LEGIT_ACCESS_KEY,
            action[0], action[1]
        )))
    
    # === Compromised Key Usage from Anomalous IP ===
    anomalous_start = base_time + timedelta(hours=random.randint(6, 18))
    
    # First: GetCallerIdentity (attacker tests the key)
    ts = anomalous_start
    events.append((ts, generate_cloudtrail_event(
        ts, ATTACKER_IP, LEGIT_USER, COMPROMISED_KEY,
        "sts.amazonaws.com", "GetCallerIdentity",
        region=AWS_REGION_ANOMALOUS
    )))
    
    # Then: IAM escalation sequence
    for i, action_data in enumerate(MALICIOUS_ACTIONS):
        ts = anomalous_start + timedelta(minutes=i * random.randint(1, 5))
        event_source = action_data[0]
        event_name = action_data[1]
        params = action_data[2] if len(action_data) > 2 else {}
        
        events.append((ts, generate_cloudtrail_event(
            ts, ATTACKER_IP, LEGIT_USER, COMPROMISED_KEY,
            event_source, event_name,
            request_params=params,
            region=AWS_REGION_ANOMALOUS
        )))
    
    # Failed actions (access denied - adds realism)
    for _ in range(5):
        ts = anomalous_start + timedelta(minutes=random.randint(20, 60))
        events.append((ts, generate_cloudtrail_event(
            ts, ATTACKER_IP, LEGIT_USER, COMPROMISED_KEY,
            "iam.amazonaws.com", "DeleteAccountPasswordPolicy",
            error_code="AccessDenied",
            region=AWS_REGION_ANOMALOUS
        )))
    
    # Console login attempt from anomalous location
    console_time = anomalous_start + timedelta(hours=1)
    console_event = generate_cloudtrail_event(
        console_time, ATTACKER_IP, LEGIT_USER, COMPROMISED_KEY,
        "signin.amazonaws.com", "ConsoleLogin",
        region=AWS_REGION_ANOMALOUS
    )
    console_event["additionalEventData"] = {
        "LoginTo": f"https://console.aws.amazon.com/console/home?region={AWS_REGION_ANOMALOUS}",
        "MobileVersion": "No",
        "MFAUsed": "No"
    }
    events.append((console_time, console_event))
    
    attack_metadata.append({
        "attack_type": "aws_iam_escalation",
        "mitre_technique": "T1078.004",
        "mitre_tactic": "Privilege Escalation",
        "compromised_key": COMPROMISED_KEY,
        "compromised_user": LEGIT_USER,
        "attacker_ip": ATTACKER_IP,
        "legitimate_region": AWS_REGION_LEGIT,
        "anomalous_region": AWS_REGION_ANOMALOUS,
        "start_time": anomalous_start.isoformat(),
        "actions_performed": len(MALICIOUS_ACTIONS),
        "severity": "CRITICAL"
    })
    
    attack_metadata.append({
        "attack_type": "aws_compromised_credentials",
        "mitre_technique": "T1098.001",
        "mitre_tactic": "Persistence",
        "detail": "New access key and user created for persistent access",
        "new_user_created": "svc-cloudops",
        "start_time": anomalous_start.isoformat(),
        "severity": "CRITICAL"
    })
    
    # Sort
    events.sort(key=lambda x: x[0])
    
    # Write CloudTrail events
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ct_path = os.path.join(OUTPUT_DIR, "cloudtrail_events.json")
    ct_data = {
        "Records": [e[1] for e in events]
    }
    with open(ct_path, "w") as f:
        json.dump(ct_data, f, indent=2)
    
    metadata_path = os.path.join(OUTPUT_DIR, "cloud_abuse_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(attack_metadata, f, indent=2)
    
    print(f"[+] Generated {len(events)} CloudTrail events → {ct_path}")
    print(f"[+] Attack metadata → {metadata_path}")
    
    return events, attack_metadata


if __name__ == "__main__":
    generate_cloud_abuse_logs()
