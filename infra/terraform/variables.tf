variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "grc-guardian"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "owner" {
  description = "Owner tag value"
  type        = string
  default     = "security"
}

variable "access_key_max_age" {
  description = "Maximum age for IAM access keys in days"
  type        = number
  default     = 90
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project = "grc-guardian"
    Owner   = "security"
  }
}
