terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_kms_key" "dlq_kms" {
  description             = "KMS key for DLQ S3 server-side encryption"
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "dlq_bucket" {
  bucket = var.dlq_bucket_name
  acl    = "private"

  # Note: If you enable DLQ archive-on-success in the application (DLQ_ARCHIVE_ON_SUCCESS=true),
  # use the `archive/` prefix (or customize) and configure lifecycle rules here to expire archived
  # objects after your desired retention (e.g. 90 days). The `dlq_retention_days` variable is used
  # in the lifecycle_rule below to purge objects automatically.

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.dlq_kms.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    id      = "dlq-expire"
    enabled = true
    expiration {
      days = var.dlq_retention_days
    }
    abort_incomplete_multipart_upload_days = 7
  }
}

resource "aws_sqs_queue" "dlq_queue" {
  name                      = var.dlq_queue_name
  visibility_timeout_seconds = 300
  message_retention_seconds  = 1209600
}

resource "aws_iam_role" "connector_role" {
  name = "janusec_connector_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = { Service = var.connector_assume_principal }
    }]
  })
}

resource "aws_iam_policy" "dlq_policy" {
  name        = "janusec_dlq_policy"
  description = "Least privilege for DLQ S3/KMS/SQS operations"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ],
        Resource = [
          "${aws_s3_bucket.dlq_bucket.arn}",
          "${aws_s3_bucket.dlq_bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = ["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey"],
        Resource = ["${aws_kms_key.dlq_kms.arn}"]
      },
      {
        Effect = "Allow",
        Action = ["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes"],
        Resource = ["${aws_sqs_queue.dlq_queue.arn}"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_dlq_policy" {
  role       = aws_iam_role.connector_role.name
  policy_arn = aws_iam_policy.dlq_policy.arn
}
