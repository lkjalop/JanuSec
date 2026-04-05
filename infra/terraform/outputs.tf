output "dlq_s3_bucket" {
  description = "Name of the DLQ S3 bucket"
  value       = aws_s3_bucket.dlq_bucket.id
}

output "dlq_s3_bucket_arn" {
  description = "ARN of the DLQ S3 bucket"
  value       = aws_s3_bucket.dlq_bucket.arn
}

output "dlq_sqs_url" {
  description = "SQS Queue URL for DLQ pointers"
  value       = aws_sqs_queue.dlq_queue.url
}

output "dlq_sqs_arn" {
  description = "SQS Queue ARN"
  value       = aws_sqs_queue.dlq_queue.arn
}

output "dlq_kms_arn" {
  description = "KMS Key ARN used for S3 SSE"
  value       = aws_kms_key.dlq_kms.arn
}
