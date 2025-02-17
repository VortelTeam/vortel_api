resource "aws_dynamodb_table" "file_metadata" {
  name         = "${var.project_name}-file-metadata-${var.environment}"
  billing_mode = "PAY_PER_REQUEST" # Or use PROVISIONED with read/write capacity units
  hash_key     = "user_id"
  range_key    = "file_id"
  

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "file_id"
    type = "S"
  }

  attribute {
    name = "upload_date"
    type = "S"
  }

  # Optional: Point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  global_secondary_index {
    name            = "UploadDateIndex"
    hash_key        = "user_id"
    range_key       = "upload_date"
    projection_type = "ALL"
  }

  tags = {
    Environment = var.environment
    Project     = var.project_name
    Terraform   = "true"
  }
}
