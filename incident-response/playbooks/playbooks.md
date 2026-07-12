# Incident Response Playbooks

## Playbook: Compromised IAM Credentials

### Detection
- GuardDuty finding: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`
- CloudTrail: API calls from unusual IP or region
- Security Hub: IAM credential findings

### Response Steps
1. **Immediate** (0-15 min)
   - Disable the compromised IAM access keys
   - Revoke active sessions via `sts:RevokeSession`
   - Notify security team via SNS alert

2. **Investigation** (15-60 min)
   - Review CloudTrail logs for all actions taken by compromised credentials
   - Identify all resources created/modified by compromised credentials
   - Check for privilege escalation attempts

3. **Remediation** (1-4 hrs)
   - Rotate all credentials for the affected user
   - Remove any unauthorized resources created during compromise
   - Update IAM policies if privilege escalation was attempted
   - Document findings in incident tracker

### Automated Remediation (EventBridge + Lambda)
- Auto-disable compromised IAM access keys on GuardDuty finding
- Auto-revoke active sessions
- Auto-notify security team

---

## Playbook: EC2 Instance Compromise

### Detection
- GuardDuty finding: `Backdoor:EC2/DNSRequest`
- GuardDuty finding: `Trojan:EC2/PhishingDomain`
- Inspector finding: Critical CVE on instance
- CloudWatch: unusual outbound traffic

### Response Steps
1. **Immediate** (0-15 min)
   - Isolate the compromised EC2 instance (remove from auto-scaling, change security group to isolation SG)
   - Create EBS snapshot for forensic analysis
   - Notify security team

2. **Investigation** (15-60 min)
   - Analyze VPC Flow Logs for unusual outbound connections
   - Review CloudTrail for instance-related API calls
   - Check GuardDuty findings for the instance

3. **Remediation** (1-4 hrs)
   - Terminate compromised instance after snapshot
   - Launch replacement from clean AMI
   - Patch any vulnerabilities identified by Inspector
   - Update security group rules

### Automated Remediation (EventBridge + Lambda)
- Auto-isolate EC2 instance on GuardDuty finding
- Auto-snapshot EBS volumes
- Auto-notify SNS topic

---

## Playbook: S3 Bucket Data Exfiltration

### Detection
- GuardDuty finding: `Exfiltration:S3/LargeObjectDownload`
- CloudTrail: unusual GetObject/BatchGetObject patterns
- Macie: sensitive data access alerts

### Response Steps
1. **Immediate** (0-15 min)
   - Block public access if enabled
   - Revoke all presigned URLs
   - Enable S3 server access logging if not active
   - Notify data owner and security team

2. **Investigation** (15-60 min)
   - Review S3 access logs for exfiltrated objects
   - Identify the IAM identity used
   - Determine data classification of exfiltrated objects

3. **Remediation** (1-4 hrs)
   - Rotate credentials used for exfiltration
   - Apply bucket policy restricting access
   - Enable MFA Delete on sensitive buckets
   - Report to compliance team if regulated data was involved

### Automated Remediation (EventBridge + Lambda)
- Auto-block public access on detection
- Auto-notify security team

---

## Playbook: DDoS Attack

### Detection
- CloudWatch: abnormal traffic patterns
- GuardDuty finding: `Recon:IAMUser/MaliciousIPCaller`
- AWS Shield Advanced alerts

### Response Steps
1. **Immediate** (0-15 min)
   - Enable Shield Advanced if available
   - Activate pre-configured WAF rate limiting rules
   - Contact AWS Support (Enterprise/Business)

2. **Investigation** (15-60 min)
   - Analyze WAF logs for attack patterns
   - Review CloudWatch metrics for traffic volumes
   - Identify attack vectors

3. **Remediation** (1-4 hrs)
   - Update WAF rules to block attack sources
   - Scale infrastructure using Auto Scaling
   - Review and update rate limiting thresholds

---

## Playbook: Ransomware

### Detection
- GuardDuty: `CryptoCurrency:EC2/BitcoinTool.B`
- Macie: sudden encryption of S3 objects
- CloudWatch: unusual CPU/disk activity

### Response Steps
1. **Immediate** (0-15 min)
   - Isolate affected instances
   - Verify backup integrity
   - Do NOT pay ransom - escalate to management

2. **Investigation** (15-60 min)
   - Determine scope of encryption
   - Identify attack vector (phishing, vulnerable service, etc.)
   - Check if data was exfiltrated before encryption

3. **Remediation** (1-24 hrs)
   - Restore from clean backups
   - Patch vulnerability used for initial access
   - Rotate all potentially compromised credentials
   - Report to law enforcement if required