variable "aws_region" {
  type = string
}

variable "org_id" {
  type = string
}

variable "primary_domain" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_iam_account_password_policy" "strict" {
  allow_users_to_change_password = true
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

data "aws_iam_users" "all" {}

resource "aws_iam_user_policy_attachment" "force_mfa" {
  for_each = toset(data.aws_iam_users.all.arns)

  user       = split("/", each.value)[length(split("/", each.value)) - 1]
  policy_arn = aws_iam_policy.force_mfa.arn
}

resource "aws_iam_policy" "force_mfa" {
  name        = "ForceMFAPolicy"
  description = "Requires MFA for all interactive users and denies actions without MFA"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowManageOwnMFADevice"
        Effect = "Allow"
        Action = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices"
        ]
        Resource = "arn:aws:iam::*:mfa/$${aws:username}"
      },
      {
        Sid    = "AllowManageOwnAccessKeys"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey"
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
      {
        Sid    = "DenyAllWithoutMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "quarterly_access_review" {
  name        = "QuarterlyAccessReviewPolicy"
  description = "Policy for automated quarterly access review - identifies inactive users and stale credentials"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMAccessReview"
        Effect = "Allow"
        Action = [
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:GetLoginProfile"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_accessanalyzer_analyzer" "organization" {
  analyzer_name = "npci-org-access-analyzer"
  type          = "ORGANIZATION"

  tags = merge(var.tags, {
    Name = "npci-org-access-analyzer"
  })
}

resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "npci-account-access-analyzer"
  type          = "ACCOUNT_UNUSED_ACCESS"

  tags = merge(var.tags, {
    Name = "npci-account-access-analyzer"
  })
}

resource "aws_iam_policy" "access_analyzer_integration" {
  name        = "AccessAnalyzerIntegrationPolicy"
  description = "Policy to enable IAM Access Analyzer findings integration with Security Hub"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AccessAnalyzerIntegration"
        Effect = "Allow"
        Action = [
          "access-analyzer:GetAnalyzer",
          "access-analyzer:GetFinding",
          "access-analyzer:ListFindings",
          "access-analyzer:ListAnalyzers"
        ]
        Resource = "*"
      }
    ]
  })
}