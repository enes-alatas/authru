# Authru - Terraform Infrastructure

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
  backend "s3" {
    bucket = "authru-terraform-state"
    key    = "authru/terraform.tfstate"
    region = "eu-west-1"
    use_lockfile = true
    encrypt = true
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AUTHRUProxy"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Local values for reuse
locals {
  function_name = "authru-${var.environment}"
  api_name      = "authru-api-${var.environment}"

  common_tags = {
    Project     = "AUTHRUProxy"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
