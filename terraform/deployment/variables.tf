# Terraform Variables for Authru

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 7

  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_size >= 128 && var.lambda_memory_size <= 10240
    error_message = "Lambda memory size must be between 128 and 10240 MB."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30

  validation {
    condition     = var.lambda_timeout >= 1 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 1 and 900 seconds."
  }
}

variable "api_stage_name" {
  description = "API Gateway stage name"
  type        = string
  default     = "prod"
}

variable "enable_api_gateway_logging" {
  description = "Enable API Gateway access logging"
  type        = bool
  default     = true
}

variable "enable_xray_tracing" {
  description = "Enable X-Ray tracing for Lambda"
  type        = bool
  default     = false
}

variable "create_example_parameter" {
  description = "Create example Parameter Store parameter"
  type        = bool
  default     = true
}

# Configuration Source Variables
variable "use_s3_config" {
  description = "Use S3 for configuration instead of Lambda Layer"
  type        = bool
  default     = true
}

variable "config_s3_bucket_name" {
  description = "S3 bucket name for configuration (if use_s3_config is true). If empty, will create a bucket with name pattern authru-config-{environment}-{random}"
  type        = string
  default     = ""
}

variable "config_s3_key" {
  description = "S3 key for the configuration file"
  type        = string
  default     = "routes.json"
}

variable "upload_config_to_s3" {
  description = "Automatically upload config/routes.json to S3 (only if use_s3_config is true)"
  type        = bool
  default     = true
}
