data "aws_s3_bucket" "infra_storage" {
  bucket = "vortel-backend-storage"
}

module "api" {
  source                = "../modules/api"
  environment           = var.environment
  project_name          = local.project_name
  lambda_storage_bucket = data.aws_s3_bucket.infra_storage.bucket
  jobs_queue            = module.processing_jobs.jobs_queue
  jobs_status_table     = module.processing_jobs.jobs_status_table
  output_bucket         = module.storage.file_process_output_bucket
  user_files_bucket     = module.storage.user_files_bucket
}

module "storage" {
  source       = "../modules/storage"
  environment  = var.environment
  project_name = local.project_name
}

module "processing_jobs" {
  source                = "../modules/processing_jobs"
  environment           = var.environment
  project_name          = local.project_name
  lambda_storage_bucket = data.aws_s3_bucket.infra_storage.bucket
  user_files_bucket     = module.storage.user_files_bucket
  output_bucket         = module.storage.file_process_output_bucket
}
