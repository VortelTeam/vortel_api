module "file_process_output" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket                  = "${var.project_name}-${var.environment}-file-process-output"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "user_files_storage" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "${var.project_name}-${var.environment}-user-files"

  versioning = {
    enabled = true
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
