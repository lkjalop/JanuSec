# ── EventBridge Event Bus ─────────────────────────────────────────────────────
resource "aws_cloudwatch_event_bus" "janusec" {
  name = "${var.project}-${var.environment}"
  tags = var.tags
}

# ── SQS Target Queue ─────────────────────────────────────────────────────────
resource "aws_sqs_queue" "events" {
  name                       = "${var.project}-events-${var.environment}"
  message_retention_seconds  = 86400
  visibility_timeout_seconds = 300
  receive_wait_time_seconds  = 20  # Long polling

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.events_dlq.arn
    maxReceiveCount     = 3
  })

  # Encrypt with KMS
  kms_master_key_id                 = aws_kms_key.sqs_key.id
  kms_data_key_reuse_period_seconds = 300

  tags = merge(var.tags, { Name = "${var.project}-events" })
}

resource "aws_sqs_queue" "events_dlq" {
  name                      = "${var.project}-events-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days

  tags = merge(var.tags, { Name = "${var.project}-events-dlq" })
}

resource "aws_kms_key" "sqs_key" {
  description             = "KMS key for JanuSec SQS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_kms_alias" "sqs_key_alias" {
  name          = "alias/${var.project}-sqs-${var.environment}"
  target_key_id = aws_kms_key.sqs_key.key_id
}

# Allow EventBridge to send messages to the SQS queue
resource "aws_sqs_queue_policy" "events_eb_policy" {
  queue_url = aws_sqs_queue.events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeSend"
        Effect = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.events.arn
        Condition = {
          ArnEquals = { "aws:SourceArn" = [for r in aws_cloudwatch_event_rule.rules : r.arn] }
        }
      }
    ]
  })
}

# ── EventBridge Rules ─────────────────────────────────────────────────────────
# One rule per entry in var.eventbridge_rules map
resource "aws_cloudwatch_event_rule" "rules" {
  for_each = var.eventbridge_rules

  name           = "${var.project}-${each.key}-${var.environment}"
  event_bus_name = aws_cloudwatch_event_bus.janusec.name
  event_pattern  = each.value
  is_enabled     = true

  tags = merge(var.tags, { RuleType = each.key })
}

resource "aws_cloudwatch_event_target" "sqs_targets" {
  for_each = aws_cloudwatch_event_rule.rules

  rule           = each.value.name
  event_bus_name = aws_cloudwatch_event_bus.janusec.name
  target_id      = "janusec-sqs"
  arn            = aws_sqs_queue.events.arn

  # Transform to add source_rule metadata
  input_transformer {
    input_paths = {
      source       = "$.source"
      detail_type  = "$.detail-type"
      account      = "$.account"
      region       = "$.region"
      time         = "$.time"
      detail       = "$.detail"
    }
    input_template = <<-EOT
    {
      "source": "<source>",
      "detail_type": "<detail_type>",
      "account": "<account>",
      "region": "<region>",
      "time": "<time>",
      "source_rule": "${each.key}",
      "detail": <detail>
    }
    EOT
  }
}

# ── IAM: EventBridge role to write to SQS (if needed for cross-account) ─────
resource "aws_iam_role" "eventbridge_role" {
  name = "${var.project}-eventbridge-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "eventbridge_sqs_policy" {
  name = "sqs-send"
  role = aws_iam_role.eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = aws_sqs_queue.events.arn
    }]
  })
}

# ── JanuSec SQS Reader Role ──────────────────────────────────────────────────
resource "aws_iam_role" "janusec_sqs_reader" {
  name = "${var.project}-sqs-reader-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = var.janusec_account_id != "" ? "arn:aws:iam::${var.janusec_account_id}:root" : "*"
        }
        Action    = "sts:AssumeRole"
        Condition = var.janusec_account_id != "" ? {
          StringEquals = { "sts:ExternalId" = "${var.project}-sqs-reader" }
        } : {}
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "janusec_sqs_reader_policy" {
  name = "sqs-read"
  role = aws_iam_role.janusec_sqs_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = aws_sqs_queue.events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.sqs_key.arn
      }
    ]
  })
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "eventbridge_bus_name" {
  value = aws_cloudwatch_event_bus.janusec.name
}

output "eventbridge_bus_arn" {
  value = aws_cloudwatch_event_bus.janusec.arn
}

output "events_sqs_url" {
  value = aws_sqs_queue.events.url
}

output "events_sqs_arn" {
  value = aws_sqs_queue.events.arn
}

output "sqs_reader_role_arn" {
  value = aws_iam_role.janusec_sqs_reader.arn
}

output "eventbridge_rule_arns" {
  value = { for k, r in aws_cloudwatch_event_rule.rules : k => r.arn }
}
