variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "npci-blocked-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  tags = var.tags
}

resource "aws_wafv2_ip_set" "trusted_ips" {
  name               = "npci-trusted-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  tags = var.tags
}

resource "aws_wafv2_regex_pattern_set" "sql_injection" {
  name  = "npci-sql-injection-patterns"
  scope = "REGIONAL"

  regular_expression_list = [
    "(?i)(?:union.*select)",
    "(?i)(?:insert.*into)",
    "(?i)(?:delete.*from)",
    "(?i)(?:drop.*table)",
    "(?i)(?:exec\\()",
    "(?i)(?:xp_cmdshell)"
  ]

  tags = var.tags
}

resource "aws_wafv2_web_acl" "npci_waf" {
  name        = "npci-owasp-waf"
  description = "WAF ACL aligned with OWASP Top 10 for NPCI applications"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "commonruleset"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "anonymousiplist"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "ipreputationlist"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "knownbadinputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "sqliruleset"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 60

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "ratelimit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "BlockMaliciousIPs"
    priority = 70

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "blockedips"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "npci-waf"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    Name = "npci-owasp-waf"
  })
}

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws/waf/npci-waf-logs"
  retention_in_days = 90

  tags = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "npci" {
  resource_arn = aws_wafv2_web_acl.npci_waf.arn

  log_destination_configs = [
    aws_cloudwatch_log_group.waf_logs.arn
  ]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}

output "waf_arn" {
  value = aws_wafv2_web_acl.npci_waf.arn
}

output "waf_id" {
  value = aws_wafv2_web_acl.npci_waf.id
}