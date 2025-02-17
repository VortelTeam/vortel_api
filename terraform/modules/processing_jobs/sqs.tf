resource "aws_sqs_queue" "batch_inference_dlq" {
  name = "${var.project_name}-${var.environment}-batch-inference-dlq"
}
resource "aws_sqs_queue" "batch_inference_queue" {
  name                       = "${var.project_name}-${var.environment}-batch-inference-queue"
  visibility_timeout_seconds = 900

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.batch_inference_dlq.arn
    maxReceiveCount     = 1
  })
}
