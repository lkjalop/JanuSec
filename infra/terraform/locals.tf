locals {
  name_prefix = lookup(var, "name_prefix", "janusec")
  dlq_bucket_name = var.dlq_bucket_name
  dlq_queue_name  = var.dlq_queue_name
}
