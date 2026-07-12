module "kms" {
  source = "./kms"

  aws_region = var.aws_region
  tags       = var.tags
}

module "s3_access_logs" {
  source = "./s3-access-logs"

  aws_region = var.aws_region
  kms_key_id = module.kms.kms_key_arns.confidential
  tags       = var.tags
}

module "data_classification" {
  source = "./data-classification"

  aws_region = var.aws_region
  tags       = var.tags
}

output "kms_key_arns" {
  value = module.kms.kms_key_arns
}

output "s3_access_logs_bucket" {
  value = module.s3_access_logs.s3_access_logs_bucket
}

output "data_classification_tag_policy_arn" {
  value = module.data_classification.data_classification_tag_policy_arn
}