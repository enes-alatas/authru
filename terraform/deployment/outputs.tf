# Terraform Outputs

output "api_gateway_url" {
  description = "API Gateway URL for Authru"
  value       = aws_api_gateway_stage.proxy_stage.invoke_url
}

output "api_gateway_id" {
  description = "API Gateway ID"
  value       = aws_api_gateway_rest_api.proxy_api.id
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.proxy_function.function_name
}

output "lambda_function_arn" {
  description = "Lambda function ARN"
  value       = aws_lambda_function.proxy_function.arn
}

output "parameter_store_prefix" {
  description = "Parameter Store prefix for API tokens"
  value       = "/authru/tokens/"
}

output "lambda_log_group_name" {
  description = "Lambda CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "api_gateway_log_group_name" {
  description = "API Gateway CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.api_gateway_logs.name
}

# S3 Configuration Bucket Outputs
output "config_s3_bucket_name" {
  description = "S3 bucket name for configuration (if S3 config is enabled)"
  value       = var.use_s3_config ? aws_s3_bucket.config_bucket[0].id : null
}

output "config_s3_bucket_arn" {
  description = "S3 bucket ARN for configuration (if S3 config is enabled)"
  value       = var.use_s3_config ? aws_s3_bucket.config_bucket[0].arn : null
}

output "config_s3_key" {
  description = "S3 key for configuration file (if S3 config is enabled)"
  value       = var.use_s3_config ? var.config_s3_key : null
}

output "config_source" {
  description = "Configuration source being used (s3 or lambda_layer)"
  value       = var.use_s3_config ? "s3" : "lambda_layer"
}
