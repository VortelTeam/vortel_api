module "file_process_output" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket                  = "${var.project_name}-${var.environment}-file-process-output"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  force_destroy = true
}

module "user_files_storage" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "${var.project_name}-${var.environment}-user-files"

  force_destroy = true

  versioning = {
    enabled = true
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  cors_rule = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT", "POST"]
      allowed_origins = ["https://your-domain.com"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    }
  ]
}
