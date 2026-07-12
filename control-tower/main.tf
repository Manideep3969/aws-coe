variable "aws_region" {
  type = string
}

variable "org_id" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "audit_account_id" {
  type = string
}

variable "log_archive_account_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_controltower_landing_zone" "npci" {
  name = "npci-landing-zone"

  manifest_json = jsonencode({
    schemaVersion = "2023-11-27"
    governanceRegions = [var.aws_region]
    managedOrganizationalUnits = [
      {
        name = "Security"
        organizationalUnitName = "Security"
      },
      {
        name = "Sandbox"
        organizationalUnitName = "Sandbox"
      },
      {
        name = "Production"
        organizationalUnitName = "Production"
      },
      {
        name = "NonProduction"
        organizationalUnitName = "NonProduction"
      }
    ]
    organizationalUnits = [
      {
        name = "Security"
      },
      {
        name = "Sandbox"
      },
      {
        name = "Production"
      },
      {
        name = "NonProduction"
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "npci-control-tower"
  })
}

resource "aws_s3_bucket" "control_tower_logs" {
  bucket = "npci-control-tower-logs-${var.management_account_id}"
}

resource "aws_s3_bucket_versioning" "control_tower_logs" {
  bucket = aws_s3_bucket.control_tower_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "control_tower_logs" {
  bucket = aws_s3_bucket.control_tower_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "control_tower_logs" {
  bucket = aws_s3_bucket.control_tower_logs.id

  block_public_acls       = true
  block_public_policy      = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "control_tower_logs" {
  bucket = aws_s3_bucket.control_tower_logs.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

output "status" {
  value = aws_controltower_landing_zone.npci.drift_status
}