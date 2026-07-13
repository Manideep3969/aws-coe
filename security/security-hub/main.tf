variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_securityhub_account" "npci" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.5.0"
  depends_on    = [aws_securityhub_account.npci]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.npci]
}

resource "aws_securityhub_standards_subscription" "nist" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.npci]
}

resource "aws_securityhub_organization_configuration" "npci" {
  auto_enable = true
}

resource "aws_securityhub_insight" "critical_findings" {
  name = "NPCI Critical Security Findings"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }

    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
  }

  group_by_attribute = "ResourceId"
}

resource "aws_securityhub_insight" "compliance_failures" {
  name = "NPCI Compliance Failures"

  filters {
    type {
      comparison = "EQUALS"
      value      = "Software and Configuration Checks"
    }

    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  group_by_attribute = "ComplianceControlId"
}

output "security_hub_arn" {
  value = aws_securityhub_account.npci.id
}