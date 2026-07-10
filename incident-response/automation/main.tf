variable "aws_region" {
  type = string
}

variable "management_account_id" {
  type = string
}

variable "audit_account_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_sns_topic" "security_incidents" {
  name              = "npci-security-incidents"
  kms_master_key_id = "alias/aws/sns"

  tags = merge(var.tags, {
    Name = "npci-security-incidents"
  })
}

resource "aws_sns_topic_subscription" "security_team_email" {
  topic_arn = aws_sns_topic.security_incidents.arn
  protocol  = "email"
  endpoint  = "security@npci.org.in"
}

resource "aws_sns_topic_subscription" "security_team_sms" {
  topic_arn = aws_sns_topic.security_incidents.arn
  protocol  = "sms"
  endpoint  = "+91XXXXXXXXXX"
}

resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  name        = "npci-guardduty-finding-rule"
  description = "Route GuardDuty findings to automated remediation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail_type = ["GuardDuty Finding"]
    detail = {
      severity = [{
        numeric = [">=", 4]
      }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_remediation" {
  rule      = aws_cloudwatch_event_rule.guardduty_finding.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_incidents.arn
}

resource "aws_cloudwatch_event_rule" "security_hub_finding" {
  name        = "npci-security-hub-finding-rule"
  description = "Route Security Hub critical findings to automated remediation"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail_type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        ComplianceStatus = [{
          comparison = "EQUALS"
          value      = "FAILED"
        }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "security_hub_remediation" {
  rule      = aws_cloudwatch_event_rule.security_hub_finding.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_incidents.arn
}

resource "aws_iam_role" "auto_remediation" {
  name = "npci-auto-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_policy" "auto_remediation" {
  name        = "npci-auto-remediation-policy"
  description = "Policy for automated security remediation actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:ReplaceIamInstanceProfileAssociation",
          "ec2:CreateSnapshot",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3Remediation"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Sid    = "SGRemediation"
        Effect = "Allow"
        Action = [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Sid    = "Logging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSM"
        Effect = "Allow"
        Action = [
          "ssm:StartAutomationExecution",
          "ssm:GetAutomationExecution"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "auto_remediation" {
  role       = aws_iam_role.auto_remediation.name
  policy_arn  = aws_iam_policy.auto_remediation.arn
}

resource "aws_lambda_function" "isolate_ec2" {
  filename      = "isolate_ec2.zip"
  function_name  = "npci-isolate-compromised-ec2"
  role          = aws_iam_role.auto_remediation.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 60

  environment {
    variables = {
      ISOLATION_SG_ID = aws_security_group.isolation.id
      SNS_TOPIC_ARN   = aws_sns_topic.security_incidents.arn
    }
  }

  tags = var.tags
}

resource "aws_security_group" "isolation" {
  name        = "npci-ec2-isolation-sg"
  description = "Security group for isolating compromised EC2 instances - denies all traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "npci-ec2-isolation-sg"
  })
}

variable "vpc_id" {
  type = string
}

resource "aws_lambda_function" "disable_iam_key" {
  filename      = "disable_iam_key.zip"
  function_name  = "npci-disable-compromised-iam-key"
  role          = aws_iam_role.auto_remediation.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_incidents.arn
    }
  }

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "guardduty_iam_compromise" {
  name        = "npci-guardduty-iam-compromise"
  description = "Trigger auto-remediation for IAM credential compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail_type = ["GuardDuty Finding"]
    detail = {
      finding = {
        Type = [{
          prefix = "UnauthorizedAccess:IAM"
        }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "disable_key_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_iam_compromise.name
  target_id = "DisableIAMKey"
  arn       = aws_lambda_function.disable_iam_key.arn
}

resource "aws_cloudwatch_event_rule" "guardduty_ec2_compromise" {
  name        = "npci-guardduty-ec2-compromise"
  description = "Trigger auto-remediation for EC2 compromise"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail_type = ["GuardDuty Finding"]
    detail = {
      finding = {
        Type = [{
          prefix = "Backdoor:EC2"
        }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "isolate_ec2_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_ec2_compromise.name
  target_id = "IsolateEC2"
  arn       = aws_lambda_function.isolate_ec2.arn
}

output "security_incidents_topic_arn" {
  value = aws_sns_topic.security_incidents.arn
}

output "auto_remediation_role_arn" {
  value = aws_iam_role.auto_remediation.arn
}