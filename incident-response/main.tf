module "automation" {
  source = "./automation"

  aws_region           = var.aws_region
  management_account_id = var.management_account_id
  audit_account_id     = var.audit_account_id
  vpc_id               = var.vpc_id
  tags                 = var.tags
}

variable "vpc_id" {
  type = string
}

output "security_incidents_topic_arn" {
  value = module.automation.security_incidents_topic_arn
}

output "auto_remediation_role_arn" {
  value = module.automation.auto_remediation_role_arn
}