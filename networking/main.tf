variable "aws_region" {
  type = string
}

variable "tags" {
  type = map(string)
}

module "vpc_flow_logs" {
  source = "./vpc-flow-logs"

  aws_region = var.aws_region
  tags       = var.tags
}

module "network_firewall" {
  source = "./network-firewall"

  aws_region         = var.aws_region
  vpc_id             = var.vpc_id
  vpc_cidr           = var.vpc_cidr
  firewall_subnet_id = var.firewall_subnet_id
  tags               = var.tags
}

module "segmentation" {
  source = "./segmentation"

  aws_region         = var.aws_region
  vpc_id             = var.vpc_id
  web_subnet_nacl_id = var.web_subnet_nacl_id
  app_subnet_cidr    = var.app_subnet_cidr
  tags               = var.tags
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "firewall_subnet_id" {
  type = string
}

variable "web_subnet_nacl_id" {
  type = string
}

variable "app_subnet_cidr" {
  type = string
}

output "vpc_flow_logs_bucket" {
  value = module.vpc_flow_logs
}

output "firewall_arn" {
  value = module.network_firewall.firewall_arn
}

output "web_tier_sg_id" {
  value = module.segmentation.web_tier_sg_id
}

output "app_tier_sg_id" {
  value = module.segmentation.app_tier_sg_id
}

output "db_tier_sg_id" {
  value = module.segmentation.db_tier_sg_id
}