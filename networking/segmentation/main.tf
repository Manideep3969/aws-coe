variable "aws_region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "tags" {
  type = map(string)
}

resource "aws_security_group" "web_tier" {
  name        = "npci-web-tier"
  description = "Security group for web tier - allows HTTPS inbound only"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }

  tags = merge(var.tags, {
    Name = "npci-web-tier"
    Tier = "web"
  })
}

resource "aws_security_group" "app_tier" {
  name        = "npci-app-tier"
  description = "Security group for application tier - allows traffic from web tier only"
  vpc_id      = var.vpc_id

  ingress {
    from_port     = 443
    to_port       = 443
    protocol      = "tcp"
    security_groups = [aws_security_group.web_tier.id]
  }

  egress {
    from_port     = 3306
    to_port       = 3306
    protocol      = "tcp"
    security_groups = [aws_security_group.db_tier.id]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "npci-app-tier"
    Tier = "application"
  })
}

resource "aws_security_group" "db_tier" {
  name        = "npci-db-tier"
  description = "Security group for database tier - allows traffic from app tier only"
  vpc_id      = var.vpc_id

  ingress {
    from_port     = 3306
    to_port       = 3306
    protocol      = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, {
    Name = "npci-db-tier"
    Tier = "database"
  })
}

resource "aws_network_acl_rule" "web_to_app" {
  network_acl_id = var.web_subnet_nacl_id
  rule_number    = 100
  rule_action    = "allow"
  from_port      = 443
  to_port        = 443
  protocol      = "6"
  cidr_block    = var.app_subnet_cidr
}

variable "web_subnet_nacl_id" {
  type = string
}

variable "app_subnet_cidr" {
  type = string
}

output "web_tier_sg_id" {
  value = aws_security_group.web_tier.id
}

output "app_tier_sg_id" {
  value = aws_security_group.app_tier.id
}

output "db_tier_sg_id" {
  value = aws_security_group.db_tier.id
}