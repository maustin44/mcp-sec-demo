variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name used for resource naming"
  type        = string
  default     = "mcp-sec-demo"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
}

variable "db_password" {
  description = "RDS PostgreSQL password for DefectDojo"
  type        = string
  sensitive   = true
}

variable "dd_secret_key" {
  description = "DefectDojo Django secret key"
  type        = string
  sensitive   = true
}
