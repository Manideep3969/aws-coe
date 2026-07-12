variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "kms_key_arn" {
  type = string
}

module "policies" {
  source = "./policies"

  aws_region  = var.aws_region
  kms_key_arn = var.kms_key_arn
  tags        = var.tags
}

output "vault_arn" {
  value = module.policies.vault_arn
}

output "plan_id" {
  value = module.policies.plan_id
}