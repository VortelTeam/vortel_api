locals {
  lambda_name = "api-router"
}

module "lambda_router" {
  source        = "terraform-aws-modules/lambda/aws"
  function_name = "${var.project_name}-${var.environment}-${local.lambda_name}"
  description   = "Lambda function for API Gateway"
  handler       = "index.lambda_handler"
  runtime       = "python3.11"
  timeout       = 90
  publish       = true
  source_path   = "${path.root}/../../lambdas/api_router"

  layers                       = ["arn:aws:lambda:${data.aws_region.current.name}:017000801446:layer:AWSLambdaPowertoolsPythonV2:79"]
  store_on_s3                  = true
  s3_bucket                    = var.lambda_storage_bucket
  trigger_on_package_timestamp = false
  environment_variables = {
  }

  role_name                = "${var.project_name}-${var.environment}-${local.lambda_name}-role"
  attach_policy_statements = true

  policy_statements = {
    bedrock = {
      effect = "Allow",
      actions = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      resources = ["*"]
    }
  }
}
