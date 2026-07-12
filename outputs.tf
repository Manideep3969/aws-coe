output "control_tower_status" {
  value       = module.control_tower.status
  description = "Control Tower deployment status"
}

output "scp_policies" {
  value       = module.scp.policy_arns
  description = "ARNs of all deployed SCP policies"
}

output "guardduty_detector_id" {
  value       = module.security.guardduty_detector_id
  description = "GuardDuty detector ID"
}

output "security_hub_arn" {
  value       = module.security.security_hub_arn
  description = "Security Hub ARN"
}

output "kms_key_arns" {
  value       = module.data_protection.kms_key_arns
  description = "ARNs of created KMS keys by classification tier"
}

output "backup_vault_arn" {
  value       = module.backup.vault_arn
  description = "Central backup vault ARN"
}