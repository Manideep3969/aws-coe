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

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    ManagedBy = "aws-coe"
    Project   = "npci-security-baseline"
  }
}