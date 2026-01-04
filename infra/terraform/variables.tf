variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "dlq_bucket_name" {
  description = "S3 bucket name for DLQ bodies"
  type        = string
}

variable "dlq_queue_name" {
  description = "SQS queue name for DLQ pointers"
  type        = string
}

variable "dlq_retention_days" {
  description = "Days to retain DLQ objects in S3"
  type        = number
  default     = 90
}

variable "connector_assume_principal" {
  description = "Principal service allowed to assume the connector role (e.g. ecs-tasks.amazonaws.com, ec2.amazonaws.com, lambda.amazonaws.com)"
  type        = string
  default     = "ecs-tasks.amazonaws.com"
}
