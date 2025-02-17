locals {
  lambda_name = "inference-lambda"
}
data "aws_region" "current" {}
data "aws_organizations_organization" "this" {}

module "lambda_router" {
  source        = "terraform-aws-modules/lambda/aws"
  function_name = "${var.project_name}-${var.environment}-${local.lambda_name}"
  description   = "Lambda function for handling inference jobs"
  handler       = "index.lambda_handler"
  runtime       = "python3.11"
  timeout       = 900
  publish       = true
  source_path   = "${path.root}/../../lambdas/inference_job_handler"

  layers                       = ["arn:aws:lambda:${data.aws_region.current.name}:017000801446:layer:AWSLambdaPowertoolsPythonV2:79"]
  store_on_s3                  = true
  s3_bucket                    = var.lambda_storage_bucket
  trigger_on_package_timestamp = false
  environment_variables = {
    INPUT_BUCKET            = var.user_files_bucket.name
    OUTPUT_BUCKET           = var.output_bucket.name
    POWERTOOLS_SERVICE_NAME = "${var.project_name}-${var.environment}-${local.lambda_name}"
    INFERENCE_JOBS_TABLE    = var.jobs_status_table.name
  }

  allowed_triggers = {
    config = {
      principal        = "config.amazonaws.com"
      principal_org_id = data.aws_organizations_organization.this.id
    }
    SQS = {
      service    = "sqs"
      source_arn = var.inference_queue.arn
    }
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
    sqs_batch_inference = {
      effect = "Allow",
      actions = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      resources = [
        var.inference_queue.arn
      ]
    }
    dynamodb_jobs_status = {
      effect = "Allow",
      actions = [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      resources = [
        var.jobs_status_table.arn,
        "${var.jobs_status_table.arn}/index/*"
      ]
    }
    bedrock = {
      effect    = "Allow"
      actions   = ["bedrock:InvokeModel"]
      resources = ["*"]
    }
  }
}

resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn                   = var.inference_queue.arn
  function_name                      = module.lambda_router.lambda_function_name
  batch_size                         = 1
  maximum_batching_window_in_seconds = 0

  # Add error handling configuration
  function_response_types = ["ReportBatchItemFailures"]
}
