variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name used as a resource name prefix"
  type        = string
  default     = "janusec"
}

variable "environment" {
  description = "Deployment environment (dev / staging / prod)"
  type        = string
  default     = "prod"
}

variable "kinesis_shard_count" {
  description = "Initial shard count for the Kinesis stream"
  type        = number
  default     = 2
}

variable "kinesis_retention_hours" {
  description = "Hours to retain records in the Kinesis stream"
  type        = number
  default     = 24
}

variable "janusec_account_id" {
  description = "AWS account ID running the JanuSec platform (cross-account trust)"
  type        = string
  default     = ""
}

variable "eventbridge_rules" {
  description = "Map of EventBridge rule name => event_pattern JSON string"
  type        = map(string)
  default = {
    "guardduty-findings"   = "{\"source\":[\"aws.guardduty\"]}"
    "securityhub-findings" = "{\"source\":[\"aws.securityhub\"]}"
    "cloudtrail-s3"        = "{\"source\":[\"aws.cloudtrail\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventCategory\":[\"Data\"]}}"
    "access-analyzer"      = "{\"source\":[\"aws.access-analyzer\"]}"
    "inspector2"           = "{\"source\":[\"aws.inspector2\"]}"
  }
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default = {
    ManagedBy   = "terraform"
    Application = "janusec"
  }
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

