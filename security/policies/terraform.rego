package terraform.security

# Basic starter policy: Disallow security groups with 0.0.0.0/0 on sensitive ports

deny[msg] {
  input.resource_type == "aws_security_group_rule"
  input.cidr_blocks[_] == "0.0.0.0/0"
  some port
  port := input.from_port
  port == 22
  msg := sprintf("Disallowed open ingress on port %d", [port])
}

deny[msg] {
  input.resource_type == "aws_security_group_rule"
  input.cidr_blocks[_] == "0.0.0.0/0"
  some port
  port := input.from_port
  port == 3389
  msg := sprintf("Disallowed open ingress on port %d", [port])
}

# Example: Enforce tags on resources
require_tags["Owner"]
require_tags["Environment"]

deny[msg] {
  input.tags == null
  msg := "Resource missing required tags"
}

deny[msg] {
  not input.tags[required]
  required := require_tags[_]
  msg := sprintf("Missing required tag: %s", [required])
}
