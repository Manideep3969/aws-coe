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

  datasources {
    s3_logs {
      enable = true
    }

    kubernetes {
      audit_logs {
        enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.tags, {
    Name = "npci-guardduty-detector"
  })
}

resource "aws_guardduty_organization_admin_account" "npci" {
  admin_account_id = var.audit_account_id
}

resource "aws_guardduty_organization_configuration" "npci" {
  auto_enable = true
  detector_id = aws_guardduty_detector.npci.id

  datasources {
    s3_logs {
      auto_enable = true
    }

    kubernetes {
      audit_logs {
        enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          auto_enable = true
        }
      }
    }
  }
}

resource "aws_guardduty_ipset" "trusted_ips" {
  detector_id     = aws_guardduty_detector.npci.id
  name            = "npci-trusted-ips"
  format          = "TXT"
  location        = "s3://npci-guardduty-ipsets/trusted-ips.txt"
  activate        = true

  tags = var.tags
}

resource "aws_guardduty_threatintelset" "threat_intel" {
  detector_id     = aws_guardduty_detector.npci.id
  name            = "npci-threat-intel"
  format          = "TXT"
  location        = "s3://npci-guardduty-ipsets/threat-intel.txt"
  activate        = true

  tags = var.tags
}