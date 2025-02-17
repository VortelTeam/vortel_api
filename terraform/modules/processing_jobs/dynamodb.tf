resource "aws_dynamodb_table" "inference_jobs_status_table" {
  name         = "${var.project_name}-inference-jobs-status-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_id"
  range_key    = "job_id"

  attribute {
    name = "job_id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }
}
