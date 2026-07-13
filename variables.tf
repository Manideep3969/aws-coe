variable "aws_region" {
  description = "Primary AWS region for Control Tower and Identity Center"
  type        = string
  default     = "ap-south-1"
}

variable "org_id" {
  description = "AWS Organizations ID"
  type        = string
}

variable "management_account_id" {
  description = "AWS account ID for the management/root account"
  type        = string
}

variable "audit_account_id" {
  description = "AWS account ID for the Control Tower audit account"
  type        = string
}

variable "log_archive_account_id" {
  description = "AWS account ID for the Control Tower log archive account"
  type        = string
}

variable "primary_domain" {
  description = "Primary domain for IAM Identity Center"
  type        = string
  default     = "npci.org.in"
}

variable "approved_regions" {
  description = "List of approved AWS regions"
  type        = list(string)
  default     = ["ap-south-1"]
}

variable "vpc_id" {
  description = "VPC ID for the security VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "firewall_subnet_id" {
  description = "Subnet ID for the network firewall"
  type        = string
}

variable "web_subnet_nacl_id" {
  description = "Network ACL ID for the web subnet"
  type        = string
}

variable "app_subnet_cidr" {
  description = "CIDR block for the application subnet"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    ManagedBy = "aws-coe"
    Project   = "npci-security-baseline"
  }
}