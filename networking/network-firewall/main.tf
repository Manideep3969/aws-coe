variable "aws_region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_networkfirewall_firewall_policy" "npci" {
  name = "npci-network-firewall-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:drop"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateless_rule_group_reference {
      priority     = 10
      resource_arn = aws_networkfirewall_rule_group.suricata_pass.arn
    }

    stateless_rule_group_reference {
      priority     = 20
      resource_arn = aws_networkfirewall_rule_group.deny_known_bad.arn
    }
  }

  tags = var.tags
}

resource "aws_networkfirewall_rule_group" "suricata_pass" {
  capacity = 100
  name     = "npci-suricata-pass"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 100
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              source {
                address_definition = "10.0.0.0/8"
              }
              source {
                address_definition = "172.16.0.0/12"
              }
              source {
                address_definition = "192.168.0.0/16"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
            }
          }
        }
      }
    }
  }

  tags = var.tags
}

resource "aws_networkfirewall_rule_group" "deny_known_bad" {
  capacity = 100
  name     = "npci-deny-known-bad"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 100
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
              destination_port {
                from_port = 22
                to_port   = 22
              }
              protocols = [6]
            }
          }
        }
        stateless_rule {
          priority = 200
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }
              destination {
                address_definition = "0.0.0.0/0"
              }
              destination_port {
                from_port = 3389
                to_port   = 3389
              }
              protocols = [6]
            }
          }
        }
      }
    }
  }

  tags = var.tags
}

resource "aws_networkfirewall_firewall" "npci" {
  name                = "npci-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.npci.arn
  vpc_id              = var.vpc_id

  subnet_mapping {
    subnet_id = var.firewall_subnet_id
  }

  tags = merge(var.tags, {
    Name = "npci-network-firewall"
  })
}

variable "firewall_subnet_id" {
  type = string
}

resource "aws_cloudwatch_log_group" "network_firewall" {
  name              = "aws/network-firewall/npci"
  retention_in_days = 90

  tags = var.tags
}

resource "aws_networkfirewall_logging_configuration" "npci" {
  firewall_arn = aws_networkfirewall_firewall.npci.arn

  logging_configuration {
    log_destination_config {
      log_type             = "ALERT"
      log_destination_type = "CloudWatchLogs"
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall.name
      }
    }

    log_destination_config {
      log_type             = "FLOW"
      log_destination_type = "CloudWatchLogs"
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall.name
      }
    }
  }
}

output "firewall_arn" {
  value = aws_networkfirewall_firewall.npci.arn
}

output "firewall_endpoint" {
  value = aws_networkfirewall_firewall.npci.firewall_status[0].sync_states[*].attachment[*].endpoint_id
}