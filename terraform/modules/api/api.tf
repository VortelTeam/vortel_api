data "aws_region" "current" {}

resource "aws_api_gateway_rest_api" "this" {
  name        = "${var.project_name}-${var.environment}"
  description = "API for ${var.project_name}-${var.environment}"

  body = templatefile("${path.module}/api.yml", {
    lambda_arn             = module.lambda_router.lambda_function_arn
    region                 = data.aws_region.current.name
    cognito_user_pool_arns = jsonencode([aws_cognito_user_pool.this.arn])
  })

  endpoint_configuration {
    types = ["EDGE"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowExecutionFromAPIGateway"
  action       = "lambda:InvokeFunction"

  function_name = module.lambda_router.lambda_function_name
  principal     = "apigateway.amazonaws.com"

  source_arn = "${aws_api_gateway_rest_api.this.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "this" {
  depends_on  = [aws_api_gateway_account.this]
  rest_api_id = aws_api_gateway_rest_api.this.id

  triggers = {
    redeployment = sha256(join("", [
      jsonencode(aws_api_gateway_rest_api.this.body),
      filemd5("${path.module}/api.yml") # Detect template changes
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "this" {
  depends_on    = [aws_api_gateway_account.this]
  deployment_id = aws_api_gateway_deployment.this.id
  rest_api_id   = aws_api_gateway_rest_api.this.id
  stage_name    = var.environment
  variables = {
    "cors" = "true"
  }

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId               = "$context.requestId"
      sourceIp                = "$context.identity.sourceIp"
      requestTime             = "$context.requestTime"
      protocol                = "$context.protocol"
      httpMethod              = "$context.httpMethod"
      resourcePath            = "$context.resourcePath"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      responseLength          = "$context.responseLength"
      integrationErrorMessage = "$context.integrationErrorMessage"
      corsOrigin              = "$context.identity.origin"
      corsRequestHeaders      = "$input.params().header.get('Access-Control-Request-Headers')"
      corsRequestMethod       = "$input.params().header.get('Access-Control-Request-Method')"
      responseHeaders         = "$context.responseHeaders.Access-Control-Allow-Headers"
      responseOrigin          = "$context.responseHeaders.Access-Control-Allow-Origin"
      responseMethods         = "$context.responseHeaders.Access-Control-Allow-Methods"
      responseCredentials     = "$context.responseHeaders.Access-Control-Allow-Credentials"
      responseMaxAge          = "$context.responseHeaders.Access-Control-Max-Age"
      responseExposeHeaders   = "$context.responseHeaders.Access-Control-Expose-Headers"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "apigateway-${var.project_name}-${var.environment}-api"
  retention_in_days = 365
}


resource "aws_iam_role" "cloudwatch" {
  name = "${var.project_name}-${var.environment}-api-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = ["apigateway.amazonaws.com", "logs.amazonaws.com", "lambda.amazonaws.com"]
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch" {
  name = "default"
  role = aws_iam_role.cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "apigateway:*"
        ]
        Resource = "arn:aws:apigateway:*::/*"
      }
    ]
  })
}

resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.cloudwatch.arn
  depends_on          = [aws_iam_role_policy.cloudwatch]
}

resource "aws_api_gateway_method_settings" "all" {
  depends_on  = [aws_api_gateway_account.this]
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}

