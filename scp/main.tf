variable "org_id" {
  type = string
}

variable "approved_regions" {
  type = list(string)
}

variable "management_account_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

locals {
  full_access_arn = "arn:aws:organizations::aws:policy/ServiceControlPolicy/AWSFullAccess"
}

resource "aws_organizations_policy" "root_protection" {
  name        = "npci-root-protection"
  description = "Prevents root account usage, blocks root API calls, restricts root credential modifications"
  content     = file("${path.module}/policies/root-protection.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-root-protection"
  })
}

resource "aws_organizations_policy" "region_lock" {
  name        = "npci-region-lock"
  description = "Limits AWS actions to approved regions only"
  content     = file("${path.module}/policies/region-lock.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-region-lock"
  })
}

resource "aws_organizations_policy" "security_service_protection" {
  name        = "npci-security-service-protection"
  description = "Prevents deletion or modification of security services (CloudTrail, GuardDuty, Config, Security Hub)"
  content     = file("${path.module}/policies/security-service-protection.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-security-service-protection"
  })
}

resource "aws_organizations_policy" "encryption_enforcement" {
  name        = "npci-encryption-enforcement"
  description = "Enforces encryption at rest for all data stores and denies unencrypted resources"
  content     = file("${path.module}/policies/encryption-enforcement.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-encryption-enforcement"
  })
}

resource "aws_organizations_policy" "public_access_prevention" {
  name        = "npci-public-access-prevention"
  description = "Prevents public access to S3 buckets, AMIs, RDS snapshots, and EBS snapshots"
  content     = file("${path.module}/policies/public-access-prevention.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-public-access-prevention"
  })
}

resource "aws_organizations_policy" "network_protection" {
  name        = "npci-network-protection"
  description = "Protects VPC configurations, security groups, NACLs, and routing tables"
  content     = file("${path.module}/policies/network-protection.json")
  type        = "SERVICE_CONTROL_POLICY"

  tags = merge(var.tags, {
    Name = "npci-network-protection"
  })
}

resource "aws_organizations_policy_attachment" "root_protection" {
  policy_id = aws_organizations_policy.root_protection.id
  target_id = var.org_id
}

resource "aws_organizations_policy_attachment" "region_lock" {
  policy_id = aws_organizations_policy.region_lock.id
  target_id = var.org_id
}

resource "aws_organizations_policy_attachment" "security_service_protection" {
  policy_id = aws_organizations_policy.security_service_protection.id
  target_id = var.org_id
}

resource "aws_organizations_policy_attachment" "encryption_enforcement" {
  policy_id = aws_organizations_policy.encryption_enforcement.id
  target_id = var.org_id
}

resource "aws_organizations_policy_attachment" "public_access_prevention" {
  policy_id = aws_organizations_policy.public_access_prevention.id
  target_id = var.org_id
}

resource "aws_organizations_policy_attachment" "network_protection" {
  policy_id = aws_organizations_policy.network_protection.id
  target_id = var.org_id
}

output "policy_arns" {
  value = {
    root_protection          = aws_organizations_policy.root_protection.arn
    region_lock              = aws_organizations_policy.region_lock.arn
    security_service_protection = aws_organizations_policy.security_service_protection.arn
    encryption_enforcement   = aws_organizations_policy.encryption_enforcement.arn
    public_access_prevention = aws_organizations_policy.public_access_prevention.arn
    network_protection       = aws_organizations_policy.network_protection.arn
  }
}