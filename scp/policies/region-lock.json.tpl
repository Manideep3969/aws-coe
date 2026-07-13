{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyActionsOutsideApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "sts:*",
        "cloudfront:*",
        "route53:*",
        "route53domains:*",
        "billing:*",
        "account:*",
        "cur:*",
        "aws-portal:*",
        "support:*",
        "trustedadvisor:*",
        "shield:*",
        "waf:*",
        "waf-regional:*",
        "ce:*",
        "health:*",
        "budgets:*",
        "chatbot:*",
        "config:*",
        "guardduty:*",
        "securityhub:*",
        "access-analyzer:*",
        "cloudtrail:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ${jsonencode(approved_regions)}
        }
      }
    }
  ]
}