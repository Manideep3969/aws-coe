# AWS Center of Excellence (CoE)

## Overview

This repository serves as the single source of truth for AWS infrastructure governance, security baselines, and operational best practices for NPCI business applications hosted on AWS.

## Current State

A Well-Architected Framework review (Security Pillar) was conducted on **April 18, 2025** for NPCI production workloads on AWS. Key findings are documented in `soc.txt`.

### What We Do Well

- IAM roles configured for AWS services
- Encryption enabled at database and S3 layers
- SSL certificates configured on ALBs
- VPC architecture and security groups in place
- CloudTrail enabled with basic CloudWatch monitoring

### Critical Gaps

| Area | Gap | Risk |
|------|-----|------|
| IAM | MFA not enforced on all users; identity center in wrong region | Critical |
| Governance | No Control Tower / landing zone; no SCPs | Critical |
| Network | No VPC flow logs; no network segmentation | High |
| Data Protection | WAF not aligned to OWASP Top 10; single KMS key for all encryption | High |
| Detection | No centralized Security Hub; no vulnerability scanning | High |
| Incident Response | No documented playbooks; no automated responses | Medium |

## Architecture Roadmap

### Phase 1 — Foundation (Days 0-7)

- [ ] Deploy AWS Control Tower in `ap-south-1` (Mumbai)
- [ ] Disable IAM Identity Center in `us-east-1`; re-enable in `ap-south-1`
- [ ] Integrate Active Directory as IdP via IAM Identity Center
- [ ] Enforce MFA for all IAM users (root accounts first)
- [ ] Enable Amazon GuardDuty across all accounts
- [ ] Configure AWS WAF on ALBs with managed rule sets
- [ ] Deploy baseline SCPs (region lock, root protection, security service protection)

### Phase 2 — Hardening (Days 7-21)

- [ ] Centralize Security Hub at organization level
- [ ] Enable AWS Config with conformance packs (CIS Benchmark)
- [ ] Deploy Amazon Inspector for vulnerability scanning
- [ ] Enable VPC Flow Logs on all VPCs
- [ ] Migrate S3 encryption from SSE-S3 to SSE-KMS with customer-managed keys
- [ ] Implement data classification tagging strategy
- [ ] Enforce SCPs for encryption, public access prevention, and resource tagging

### Phase 3 — Operations (Days 21-30)

- [ ] Establish central security team under Control Tower governance
- [ ] Document incident response playbooks
- [ ] Implement automated remediation (EventBridge + Lambda / SSM)
- [ ] Build CIS-hardened AMIs via EC2 Image Builder
- [ ] Configure AWS Backup with cross-region and cross-account policies
- [ ] Enable S3 access logs and ALB access logs

## Repository Structure

```
aws-coe/
├── README.md                   # This file
├── soc.txt                     # Original SOC review findings
├── control-tower/              # Control Tower configuration and guardrails
│   ├── manifests/              # Control Tower manifest files
│   └── guardrails/             # Preventive and detective guardrail definitions
├── scp/                        # Service Control Policies
│   ├── root-protection.json
│   ├── region-lock.json
│   ├── security-service-protection.json
│   ├── encryption-enforcement.json
│   ├── public-access-prevention.json
│   └── network-protection.json
├── security/                   # Security baselines
│   ├── guardduty/              # GuardDuty configurations
│   ├── security-hub/          # Security Hub standards and controls
│   ├── waf/                   # WAF rule definitions
│   └── inspector/             # Inspector scan configurations
├── networking/                 # Network architecture
│   ├── vpc-flow-logs/         # VPC flow log configurations
│   ├── network-firewall/      # Network Firewall policies
│   └── segmentation/          # Network segmentation templates
├── iam/                        # IAM policies and roles
│   ├── sso/                   # IAM Identity Center configurations
│   ├── mfa-enforcement/       # MFA enforcement policies
│   └── access-analyzer/       # IAM Access Analyzer rules
├── incident-response/          # Playbooks and automation
│   ├── playbooks/             # Incident response playbooks
│   └── automation/            # Automated remediation functions
└── backup/                     # Backup policies and configurations
    └── policies/              # AWS Backup vault policies
```

## Key Principles

1. **Least Privilege** — Every identity and resource gets minimum required permissions
2. **Defense in Depth** — Multiple layers: SCPs → IAM policies → Security Groups → WAF → encryption
3. **Automated Detection and Response** — GuardDuty, Security Hub, and Config for detection; EventBridge + Lambda for automated remediation
4. **Centralized Governance** — Control Tower as the single pane of glass for all account management and guardrail enforcement
5. **Region Confinement** — All workloads restricted to `ap-south-1` unless explicitly approved

## Compliance Targets

- CIS AWS Foundations Benchmark v1.5
- NPCI security guidelines
- RBI IT framework for NBFCs
- OWASP Top 10

## Contact

- **Reviewer:** Ashish Srivastava
- **Stakeholders:** NPCI Team, AWS Team