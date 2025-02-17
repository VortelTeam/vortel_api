data "aws_s3_bucket" "infra_storage" {
  bucket = "vortel-backend-storage-2"
}

module "api" {
  source                = "../modules/api"
  environment           = var.environment
  project_name          = local.project_name
  lambda_storage_bucket = data.aws_s3_bucket.infra_storage.bucket
}
