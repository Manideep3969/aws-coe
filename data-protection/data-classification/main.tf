variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "data_classification_inventory" {
  bucket = "npci-data-classification-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "data_classification_inventory" {
  bucket = aws_s3_bucket.data_classification_inventory.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_classification_inventory" {
  bucket = aws_s3_bucket.data_classification_inventory.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data_classification_inventory" {
  bucket = aws_s3_bucket.data_classification_inventory.id

  block_public_acls       = true
  block_public_policy      = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "data_classification_inventory" {
  bucket = aws_s3_bucket.data_classification_inventory.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 180
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 730
    }
  }
}

locals {
  data_classification_tags = {
    "DataClassification:Public"      = "Data that can be shared publicly"
    "DataClassification:Internal"    = "Data for internal use only"
    "DataClassification:Confidential" = "Data requiring strict access controls"
    "DataClassification:Restricted"  = "Highly sensitive data with regulatory requirements"
  }

  tag_policy = jsonencode({
    tags = {
      DataClassification = {
        tag_key   = "DataClassification"
        tag_value = ["Public", "Internal", "Confidential", "Restricted"]
      }
      DataOwner = {
        tag_key   = "DataOwner"
        tag_value = ["*"]
      }
      DataSensitivity = {
        tag_key   = "DataSensitivity"
        tag_value = ["Low", "Medium", "High", "Critical"]
      }
    }
  })
}

resource "aws_organizations_policy" "data_classification_tag_policy" {
  name        = "npci-data-classification-tag-policy"
  description = "Enforces data classification tagging on all resources"
  content     = local.tag_policy
  type        = "TAG_POLICY"

  tags = var.tags
}

resource "aws_config_config_rule" "data_classification_tag" {
  name = "npci-data-classification-tag-rule"

  source {
    owner             = "CUSTOM_LIN"
    source_identifier = "DATA_CLASSIFICATION_TAG_CHECK"
    source_detail {
      key   = "Inline"
      value = <<-EOT
        # Check that all resources have DataClassification tag
        import json
        def evaluate_compliance(configuration_item):
            tags = configuration_item.get('tags', {})
            if 'DataClassification' not in tags:
                return 'NON_COMPLIANT'
            valid_values = ['Public', 'Internal', 'Confidential', 'Restricted']
            if tags['DataClassification'] not in valid_values:
                return 'NON_COMPLIANT'
            return 'COMPLIANT'
      EOT
    }
  }

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket",
      "AWS::RDS::DBInstance",
      "AWS::EC2::Instance",
      "AWS::SQS::Queue",
      "AWS::SNS::Topic",
      "AWS::DynamoDB::Table",
      "AWS::Lambda::Function"
    ]
  }

  tags = var.tags
}

output "data_classification_tag_policy_arn" {
  value = aws_organizations_policy.data_classification_tag_policy.arn
}