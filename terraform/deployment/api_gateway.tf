# API Gateway Resources

# API Gateway CloudWatch Log Group
resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway/${local.api_name}"
  retention_in_days = var.log_retention_days
  lifecycle {
    prevent_destroy = false
    ignore_changes  = [name]
  }
  tags = local.common_tags
}

# API Gateway account settings (for CloudWatch logging)
resource "aws_api_gateway_account" "main" {
  count               = var.enable_api_gateway_logging ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.api_gateway_cloudwatch[0].arn

  depends_on = [
    aws_iam_role.api_gateway_cloudwatch,
    aws_iam_role_policy_attachment.api_gateway_cloudwatch,
  ]
}

# IAM role for API Gateway CloudWatch logging
resource "aws_iam_role" "api_gateway_cloudwatch" {
  count = var.enable_api_gateway_logging ? 1 : 0
  name  = "${local.api_name}-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach CloudWatch policy to API Gateway role
resource "aws_iam_role_policy_attachment" "api_gateway_cloudwatch" {
  role       = aws_iam_role.api_gateway_cloudwatch[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"

  depends_on = [aws_iam_role.api_gateway_cloudwatch]
}

# REST API
resource "aws_api_gateway_rest_api" "proxy_api" {
  name        = local.api_name
  description = "API Gateway for Authru service"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = local.common_tags
}

# Proxy resource (catch all paths)
resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  parent_id   = aws_api_gateway_rest_api.proxy_api.root_resource_id
  path_part   = "{proxy+}"
  depends_on  = [aws_api_gateway_rest_api.proxy_api]
}

# Lambda integration for proxy resource
resource "aws_api_gateway_integration" "lambda_proxy" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy_any.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.proxy_function.invoke_arn

  depends_on = [
    aws_api_gateway_method.proxy_any,
    aws_lambda_function.proxy_function,
  ]
}

# ANY method for proxy resource
resource "aws_api_gateway_method" "proxy_any" {
  rest_api_id   = aws_api_gateway_rest_api.proxy_api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"

  request_parameters = {
    "method.request.path.proxy" = true
  }
  depends_on = [aws_api_gateway_resource.proxy]
}

# CORS configuration for proxy resource
resource "aws_api_gateway_method" "proxy_options" {
  rest_api_id   = aws_api_gateway_rest_api.proxy_api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "OPTIONS"
  authorization = "NONE"

  depends_on = [aws_api_gateway_resource.proxy]
}

resource "aws_api_gateway_integration" "proxy_options" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy_options.http_method

  type = "MOCK"
  request_templates = {
    "application/json" = jsonencode({
      statusCode = 200
    })
  }

  depends_on = [aws_api_gateway_method.proxy_options]
}

resource "aws_api_gateway_method_response" "proxy_options" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Max-Age"       = true
  }

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.proxy_options]
}

resource "aws_api_gateway_integration_response" "proxy_options" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  resource_id = aws_api_gateway_resource.proxy.id
  http_method = aws_api_gateway_method.proxy_options.http_method
  status_code = aws_api_gateway_method_response.proxy_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With'"
    "method.response.header.Access-Control-Allow-Methods" = "'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
    "method.response.header.Access-Control-Max-Age"       = "'86400'"
  }

  depends_on = [
    aws_api_gateway_method_response.proxy_options,
    aws_api_gateway_integration.proxy_options,
  ]
}

# API Gateway deployment
resource "aws_api_gateway_deployment" "proxy_deployment" {
  depends_on = [
    aws_api_gateway_integration.lambda_proxy,
    aws_api_gateway_integration.proxy_options,
  ]

  rest_api_id = aws_api_gateway_rest_api.proxy_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.proxy.id,
      aws_api_gateway_method.proxy_any.id,
      aws_api_gateway_method.proxy_options.id,
      aws_api_gateway_integration.lambda_proxy.id,
      aws_api_gateway_integration.proxy_options.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# API Gateway stage
resource "aws_api_gateway_stage" "proxy_stage" {
  deployment_id = aws_api_gateway_deployment.proxy_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.proxy_api.id
  stage_name    = var.api_stage_name

  dynamic "access_log_settings" {
    for_each = var.enable_api_gateway_logging ? [1] : []
    content {
      destination_arn = aws_cloudwatch_log_group.api_gateway_logs.arn
      format = jsonencode({
        requestId      = "$context.requestId"
        ip             = "$context.identity.sourceIp"
        caller         = "$context.identity.caller"
        user           = "$context.identity.user"
        requestTime    = "$context.requestTime"
        httpMethod     = "$context.httpMethod"
        resourcePath   = "$context.resourcePath"
        status         = "$context.status"
        protocol       = "$context.protocol"
        responseLength = "$context.responseLength"
      })
    }
  }

  xray_tracing_enabled = var.enable_xray_tracing

  depends_on = [
    aws_api_gateway_deployment.proxy_deployment,
    aws_cloudwatch_log_group.api_gateway_logs,
  ]

  tags = local.common_tags
}

# Method settings for logging and metrics
resource "aws_api_gateway_method_settings" "proxy_settings" {
  rest_api_id = aws_api_gateway_rest_api.proxy_api.id
  stage_name  = aws_api_gateway_stage.proxy_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled    = true
    logging_level      = var.enable_api_gateway_logging ? "INFO" : "OFF"
    data_trace_enabled = false # Disabled for cost optimization
  }

  depends_on = [aws_api_gateway_stage.proxy_stage]
}
