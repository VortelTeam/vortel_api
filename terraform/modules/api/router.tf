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
    INPUT_BUCKET_NAME            = var.user_files_bucket.name
    OUTPUT_BUCKET_NAME           = var.output_bucket.name
    POWERTOOLS_SERVICE_NAME      = "${var.project_name}-${var.environment}-${local.lambda_name}"
    POWERTOOLS_METRICS_NAMESPACE = "APIGateway"
    JOBS_QUEUE_URL               = var.jobs_queue.name
    JOBS_TABLE                   = var.jobs_status_table.name
  }

  role_name                = "${var.project_name}-${var.environment}-${local.lambda_name}-role"
  attach_policy_statements = true

  policy_statements = {
    s3_files_input = {
      effect = "Allow",
      actions = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      resources = [
        var.user_files_bucket.arn,
        "${var.user_files_bucket.arn}/*"
      ]
    }
    s3_files_output = {
      effect = "Allow",
      actions = [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject"
      ],
      resources = [
        var.output_bucket.arn,
        "${var.output_bucket.arn}/*"
      ]
    }
    sqs_batch_jobs = {
      effect = "Allow",
      actions = [
        "sqs:SendMessage"
      ],
      resources = [
        var.jobs_queue.arn
      ]
    }
    dynamodb_jobs_status = {
      effect = "Allow",
      actions = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query"
      ],
      resources = [
        var.jobs_status_table.arn,
        "${var.jobs_status_table.arn}/index/*"
      ]
    }
  }
}
