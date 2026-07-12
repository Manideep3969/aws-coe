variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_inspector2_organization_configuration" "npci" {
  auto_enable {
    ec2             = true
    ecr             = true
    lambda          = true
    lambda_code     = true
  }
}

resource "aws_inspector2_enabler" "npci" {
  account_ids    = []
  resource_types  = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]

  depends_on = [aws_inspector2_organization_configuration.npci]
}

resource "aws_inspector2_filter" "critical" {
  name   = "npci-critical-findings"

  filter_criteria {
    severity = [{
      comparison = "EQUALS"
      value      = "CRITICAL"
    }]

    finding_status = [{
      comparison = "EQUALS"
      value      = "ACTIVE"
    }]
  }

  description = "Filter for critical active findings"

  tags = var.tags
}

resource "aws_inspector2_filter" "high" {
  name   = "npci-high-findings"

  filter_criteria {
    severity = [{
      comparison = "EQUALS"
      value      = "HIGH"
    }]

    finding_status = [{
      comparison = "EQUALS"
      value      = "ACTIVE"
    }]
  }

  description = "Filter for high severity active findings"

  tags = var.tags
}

output "inspector_status" {
  value = aws_inspector2_organization_configuration.npci
}