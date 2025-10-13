# S3 Bucket for Configuration (optional)

# Random suffix for bucket name uniqueness
resource "random_id" "config_bucket_suffix" {
  count       = var.use_s3_config ? 1 : 0
  byte_length = 4
}

# S3 bucket for configuration
resource "aws_s3_bucket" "config_bucket" {
  count  = var.use_s3_config ? 1 : 0
  bucket = var.config_s3_bucket_name != "" ? var.config_s3_bucket_name : "authru-config-${var.environment}-${random_id.config_bucket_suffix[0].hex}"

  tags = merge(
    local.common_tags,
    {
      Name = "Authru Configuration Bucket"
    }
  )
}

# Block public access to the configuration bucket
resource "aws_s3_bucket_public_access_block" "config_bucket_block" {
  count  = var.use_s3_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for configuration rollback
resource "aws_s3_bucket_versioning" "config_bucket_versioning" {
  count  = var.use_s3_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption for configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "config_bucket_encryption" {
  count  = var.use_s3_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Lifecycle policy to manage old configuration versions
resource "aws_s3_bucket_lifecycle_configuration" "config_bucket_lifecycle" {
  count  = var.use_s3_config ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id

  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"
    filter {
      prefix = ""
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Upload initial configuration to S3
resource "aws_s3_object" "config_file" {
  count  = var.use_s3_config && var.upload_config_to_s3 ? 1 : 0
  bucket = aws_s3_bucket.config_bucket[0].id
  key    = var.config_s3_key
  source = "${path.module}/../../config/routes.json"
  etag   = filemd5("${path.module}/../../config/routes.json")

  content_type = "application/json"

  tags = merge(
    local.common_tags,
    {
      Name = "Authru Routes Configuration"
    }
  )
}

