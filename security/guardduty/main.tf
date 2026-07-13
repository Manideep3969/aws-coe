variable "aws_region" {
  type = string
}

variable "org_id" {
  type = string
}

variable "audit_account_id" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_guardduty_detector" "npci" {
  enable = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.tags, {
    Name = "npci-guardduty-detector"
  })
}

resource "aws_guardduty_detector_feature" "s3_logs" {
  detector_id = aws_guardduty_detector.npci.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "kubernetes" {
  detector_id = aws_guardduty_detector.npci.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "malware" {
  detector_id = aws_guardduty_detector.npci.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

resource "aws_guardduty_organization_admin_account" "npci" {
  admin_account_id = var.audit_account_id
}

resource "aws_guardduty_organization_configuration" "npci" {
  detector_id                      = aws_guardduty_detector.npci.id
  auto_enable_organization_members = "ALL"
}

resource "aws_guardduty_ipset" "trusted_ips" {
  detector_id = aws_guardduty_detector.npci.id
  name        = "npci-trusted-ips"
  format      = "TXT"
  location    = "s3://npci-guardduty-ipsets/trusted-ips.txt"
  activate    = true

  tags = var.tags
}

resource "aws_guardduty_threatintelset" "threat_intel" {
  detector_id = aws_guardduty_detector.npci.id
  name        = "npci-threat-intel"
  format      = "TXT"
  location    = "s3://npci-guardduty-ipsets/threat-intel.txt"
  activate    = true

  tags = var.tags
}