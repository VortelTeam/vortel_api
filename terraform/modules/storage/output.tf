output "file_process_output_bucket" {
  value = {
    name = module.file_process_output.s3_bucket_id,
    arn  = module.file_process_output.s3_bucket_arn
  }
}

output "user_files_bucket" {
  value = {
    name = module.user_files_storage.s3_bucket_id
    arn  = module.user_files_storage.s3_bucket_arn
  }
}
