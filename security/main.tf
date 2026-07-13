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

module "guardduty" {
  source = "./guardduty"

  aws_region            = var.aws_region
  org_id                = var.org_id
  audit_account_id      = var.audit_account_id
  management_account_id = var.management_account_id
  tags                  = var.tags
}

module "security_hub" {
  source = "./security-hub"

  aws_region = var.aws_region
  tags       = var.tags
}

module "waf" {
  source = "./waf"

  aws_region = var.aws_region
  tags       = var.tags
}

module "inspector" {
  source = "./inspector"

  aws_region = var.aws_region
  tags       = var.tags
}

output "guardduty_detector_id" {
  value = module.guardduty
}

output "security_hub_arn" {
  value = module.security_hub.security_hub_arn
}

output "waf_arn" {
  value = module.waf.waf_arn
}

output "inspector_status" {
  value = module.inspector.inspector_status
}