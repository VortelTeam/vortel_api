output "jobs_queue" {
  value = {
    name = aws_sqs_queue.batch_inference_queue.name
    arn  = aws_sqs_queue.batch_inference_queue.arn
  }
}

output "jobs_status_table" {
  value = {
    name = aws_dynamodb_table.inference_jobs_status_table.name
    arn  = aws_dynamodb_table.inference_jobs_status_table.arn
  }
}
