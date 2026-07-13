variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

data "aws_vpcs" "all" {}

data "aws_vpc" "vpcs" {
  for_each = toset(data.aws_vpcs.all.ids)
  id       = each.value
}

resource "aws_s3_bucket" "vpc_flow_logs" {
  bucket = "npci-vpc-flow-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "vpc_flow_logs" {
  bucket = aws_s3_bucket.vpc_flow_logs.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_flow_log" "vpc_flow_logs" {
  for_each = toset(data.aws_vpcs.all.ids)

  vpc_id               = each.value
  traffic_type         = "ALL"
  log_destination      = aws_s3_bucket.vpc_flow_logs.arn
  log_destination_type = "s3"

  tags = merge(var.tags, {
    Name = "npci-vpc-flow-log-${each.value}"
  })
}

data "aws_caller_identity" "current" {}