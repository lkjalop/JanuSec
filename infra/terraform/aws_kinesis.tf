# ── Kinesis Data Stream ──────────────────────────────────────────────────────
resource "aws_kinesis_stream" "security_events" {
  name             = "${var.project}-security-events-${var.environment}"
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  encryption_type = "KMS"
  kms_key_id      = aws_kms_key.kinesis_key.id

  tags = merge(var.tags, {
    Name = "${var.project}-security-events"
  })
}

resource "aws_kms_key" "kinesis_key" {
  description             = "KMS key for JanuSec Kinesis stream encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = var.tags
}

resource "aws_kms_alias" "kinesis_key_alias" {
  name          = "alias/${var.project}-kinesis-${var.environment}"
  target_key_id = aws_kms_key.kinesis_key.key_id
}

# ── Kinesis Scaling Policy ───────────────────────────────────────────────────
resource "aws_appautoscaling_target" "kinesis_target" {
  max_capacity       = 10
  min_capacity       = 1
  resource_id        = "stream/${aws_kinesis_stream.security_events.name}"
  scalable_dimension = "kinesis:stream:WriteCapacityUnits"
  service_namespace  = "kinesis"
}

resource "aws_appautoscaling_policy" "kinesis_scale_up" {
  name               = "${var.project}-kinesis-scale-up"
  policy_type        = "StepScaling"
  resource_id        = aws_appautoscaling_target.kinesis_target.resource_id
  scalable_dimension = aws_appautoscaling_target.kinesis_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.kinesis_target.service_namespace

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 300
    metric_aggregation_type = "Maximum"

    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 2
    }
  }
}

# CloudWatch alarm that triggers shard scale-up when IncomingRecords > threshold
resource "aws_cloudwatch_metric_alarm" "kinesis_high_throughput" {
  alarm_name          = "${var.project}-kinesis-high-throughput"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "IncomingRecords"
  namespace           = "AWS/Kinesis"
  period              = 60
  statistic           = "Sum"
  threshold           = 800000  # 80% of default 1M/shard/min limit

  dimensions = {
    StreamName = aws_kinesis_stream.security_events.name
  }

  alarm_actions = [aws_appautoscaling_policy.kinesis_scale_up.arn]
  tags          = var.tags
}

# ── IAM: JanuSec Kinesis Reader Role ────────────────────────────────────────
resource "aws_iam_role" "janusec_kinesis_reader" {
  name = "${var.project}-kinesis-reader-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      # Cross-account trust — JanuSec platform account
      {
        Effect = "Allow"
        Principal = {
          AWS = var.janusec_account_id != "" ? "arn:aws:iam::${var.janusec_account_id}:root" : "*"
        }
        Action = "sts:AssumeRole"
        Condition = var.janusec_account_id != "" ? {
          StringEquals = { "sts:ExternalId" = "${var.project}-kinesis-reader" }
        } : {}
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "janusec_kinesis_reader_policy" {
  name = "kinesis-read"
  role = aws_iam_role.janusec_kinesis_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream",
          "kinesis:DescribeStreamSummary",
          "kinesis:ListShards",
          "kinesis:ListStreams",
          "kinesis:SubscribeToShard",
          "kinesis:RegisterStreamConsumer",
          "kinesis:DeregisterStreamConsumer",
          "kinesis:DescribeStreamConsumer"
        ]
        Resource = [
          aws_kinesis_stream.security_events.arn,
          "${aws_kinesis_stream.security_events.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.kinesis_key.arn
      }
    ]
  })
}

# ── Outputs ──────────────────────────────────────────────────────────────────
output "kinesis_stream_name" {
  value = aws_kinesis_stream.security_events.name
}

output "kinesis_stream_arn" {
  value = aws_kinesis_stream.security_events.arn
}

output "kinesis_reader_role_arn" {
  value = aws_iam_role.janusec_kinesis_reader.arn
}
