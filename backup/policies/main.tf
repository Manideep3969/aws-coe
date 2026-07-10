variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

data "aws_caller_identity" "current" {}

resource "aws_backup_vault" "npci" {
  name        = "npci-backup-vault"
  kms_key_arn = var.kms_key_arn

  tags = merge(var.tags, {
    Name = "npci-backup-vault"
  })
}

variable "kms_key_arn" {
  type = string
}

resource "aws_backup_plan" "daily" {
  name = "npci-daily-backup-plan"

  rule {
    rule_name         = "daily-backup-rule"
    target_vault_name = aws_backup_vault.npci.name
    schedule          = "cron(0 5 ? * * *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = 35
    }

    recovery_point_tags = merge(var.tags, {
      BackupType = "daily"
    })
  }

  rule {
    rule_name         = "weekly-backup-rule"
    target_vault_name = aws_backup_vault.npci.name
    schedule          = "cron(0 5 ? * SUN *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = 90
    }

    recovery_point_tags = merge(var.tags, {
      BackupType = "weekly"
    })
  }

  rule {
    rule_name         = "monthly-backup-rule"
    target_vault_name = aws_backup_vault.npci.name
    schedule          = "cron(0 5 1 * ? *)"
    start_window      = 60
    completion_window = 180

    lifecycle {
      delete_after = 365
    }

    recovery_point_tags = merge(var.tags, {
      BackupType = "monthly"
    })
  }

  tags = var.tags
}

resource "aws_backup_selection" "ec2" {
  name         = "npci-ec2-backup-selection"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:service-role/AWSBackupDefaultServiceRole"

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

resource "aws_backup_selection" "rds" {
  name         = "npci-rds-backup-selection"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:service-role/AWSBackupDefaultServiceRole"

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "rds"
  }
}

resource "aws_backup_selection" "dynamodb" {
  name         = "npci-dynamodb-backup-selection"
  plan_id      = aws_backup_plan.daily.id
  iam_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:service-role/AWSBackupDefaultServiceRole"

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "dynamodb"
  }
}

resource "aws_backup_vault_lock_configuration" "npci" {
  backup_vault_name = aws_backup_vault.npci.name
  min_retention_days = 7
  max_retention_days = 365
  changeable_for_days = 30
}

output "vault_arn" {
  value = aws_backup_vault.npci.arn
}

output "plan_id" {
  value = aws_backup_plan.daily.id
}