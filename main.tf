terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30.0"
    }
  }

  backend "s3" {
    bucket         = "npci-terraform-state"
    key            = "control-tower/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

module "control_tower" {
  source = "./control-tower"

  aws_region             = var.aws_region
  org_id                 = var.org_id
  management_account_id  = var.management_account_id
  audit_account_id       = var.audit_account_id
  log_archive_account_id = var.log_archive_account_id
  tags                   = var.tags
}

module "scp" {
  source = "./scp"

  org_id                = var.org_id
  approved_regions      = var.approved_regions
  management_account_id = var.management_account_id
  tags                  = var.tags
}

module "iam" {
  source = "./iam"

  aws_region            = var.aws_region
  org_id                = var.org_id
  primary_domain        = var.primary_domain
  management_account_id = var.management_account_id
  tags                  = var.tags
}

module "security" {
  source = "./security"

  aws_region            = var.aws_region
  org_id                = var.org_id
  audit_account_id      = var.audit_account_id
  management_account_id = var.management_account_id
  tags                  = var.tags
}

module "networking" {
  source = "./networking"

  aws_region         = var.aws_region
  vpc_id             = var.vpc_id
  vpc_cidr           = var.vpc_cidr
  firewall_subnet_id = var.firewall_subnet_id
  web_subnet_nacl_id = var.web_subnet_nacl_id
  app_subnet_cidr    = var.app_subnet_cidr
  tags               = var.tags
}

module "data_protection" {
  source = "./data-protection"

  aws_region = var.aws_region
  tags       = var.tags
}

module "incident_response" {
  source = "./incident-response"

  aws_region            = var.aws_region
  management_account_id = var.management_account_id
  audit_account_id      = var.audit_account_id
  vpc_id                = var.vpc_id
  tags                  = var.tags
}

module "backup" {
  source = "./backup"

  aws_region  = var.aws_region
  kms_key_arn = module.data_protection.kms_key_arns.confidential
  tags        = var.tags
}