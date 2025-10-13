# Lambda Function and Related Resources

# Create Lambda execution role
resource "aws_iam_role" "lambda_role" {
  name = "${local.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

  depends_on = [aws_iam_role.lambda_role]
}

# Custom policy for Parameter Store access
resource "aws_iam_role_policy" "lambda_parameter_store" {
  name = "${local.function_name}-parameter-store-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:*:parameter/authru/*"
      }
    ]
  })

  depends_on = [aws_iam_role.lambda_role]
}

# Custom policy for S3 config access (if enabled)
resource "aws_iam_role_policy" "lambda_s3_config" {
  count = var.use_s3_config ? 1 : 0
  name  = "${local.function_name}-s3-config-policy"
  role  = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = "${aws_s3_bucket.config_bucket[0].arn}/${var.config_s3_key}"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketVersioning"
        ]
        Resource = aws_s3_bucket.config_bucket[0].arn
      }
    ]
  })

  depends_on = [
    aws_iam_role.lambda_role,
    aws_s3_bucket.config_bucket
  ]
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# Create deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../src"
  output_path = "${path.module}/lambda_deployment.zip"
  excludes = [
    "**/__pycache__/**",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".pytest_cache",
    "tests"
  ]
}

# Create config layer
data "archive_file" "config_layer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../config"
  output_path = "${path.module}/config_layer.zip"
}

# Lambda layer for configuration
resource "aws_lambda_layer_version" "config_layer" {
  filename         = data.archive_file.config_layer_zip.output_path
  layer_name       = "${local.function_name}-config"
  source_code_hash = data.archive_file.config_layer_zip.output_base64sha256

  compatible_runtimes = ["python3.12"]
  description         = "Configuration layer for Authru"

  depends_on = [data.archive_file.config_layer_zip]
}

# Build Python dependencies into a Lambda layer structure
resource "null_resource" "python_deps_build" {
  # Rebuild when requirements.txt changes
  triggers = {
    requirements_sha1 = filesha1("${path.module}/../../requirements.txt")
  }

  provisioner "local-exec" {
    command = "rm -rf ${path.module}/python_deps && mkdir -p ${path.module}/python_deps/python && python3 -m pip install --upgrade pip && python3 -m pip install -r ${path.module}/../../requirements.txt -t ${path.module}/python_deps/python"
  }
}

# Zip the dependencies layer (must contain a top-level 'python/' dir)
data "archive_file" "python_deps_layer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/python_deps"
  output_path = "${path.module}/python_deps_layer.zip"

  depends_on = [null_resource.python_deps_build]
}

# Lambda layer for Python dependencies
resource "aws_lambda_layer_version" "python_deps_layer" {
  filename         = data.archive_file.python_deps_layer_zip.output_path
  layer_name       = "${local.function_name}-python-deps"
  source_code_hash = data.archive_file.python_deps_layer_zip.output_base64sha256

  compatible_runtimes = ["python3.12"]
  description         = "Python dependencies for Authru"

  depends_on = [data.archive_file.python_deps_layer_zip]
}

# Lambda function
resource "aws_lambda_function" "proxy_function" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = local.function_name
  role             = aws_iam_role.lambda_role.arn
  handler          = "handlers.proxy_handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = merge(
      {
        LOG_LEVEL         = "INFO"
        AUTHRU_CONFIG_PATH = "/opt/config/routes.json"
      },
      var.use_s3_config ? {
        AUTHRU_CONFIG_S3_BUCKET = aws_s3_bucket.config_bucket[0].id
        AUTHRU_CONFIG_S3_KEY    = var.config_s3_key
      } : {}
    )
  }

  layers = [
    aws_lambda_layer_version.config_layer.arn,
    aws_lambda_layer_version.python_deps_layer.arn
  ]

  dynamic "tracing_config" {
    for_each = var.enable_xray_tracing ? [1] : []
    content {
      mode = "Active"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy.lambda_parameter_store,
    aws_cloudwatch_log_group.lambda_logs,
    aws_lambda_layer_version.config_layer,
    aws_lambda_layer_version.python_deps_layer,
  ]
  tags = local.common_tags
}

# Lambda permission for API Gateway
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.proxy_function.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.proxy_api.execution_arn}/*/*"

  depends_on = [
    aws_lambda_function.proxy_function,
    aws_api_gateway_rest_api.proxy_api,
  ]
}
