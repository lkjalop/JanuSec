Terraform DLQ module notes

- This module creates the DLQ S3 bucket, optional KMS key, SQS queue, and IAM roles/policies.
- Variables like `dlq_enable_kms`, `dlq_kms_enable_key_rotation`, and `dlq_enforce_bucket_policy` let you toggle strict enforcement during rollout.

CI recommendation
-----------------
- Add a `terraform init` and `terraform plan` step to PR validation. Use least-privilege credentials for plan (or run in a read-only mode). Example GitHub Action snippet:

```yaml
name: Terraform PR Plan
on: [pull_request]
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v2
        with:
          terraform_version: 1.5.0
      - name: Terraform Init
        run: terraform -chdir=infra/terraform init
      - name: Terraform Plan
        run: terraform -chdir=infra/terraform plan -out=tfplan
      - name: Terraform Show
        run: terraform -chdir=infra/terraform show -no-color tfplan
```

Policy checks
-------------
- Optionally run static checks like `tflint` and `checkov` to catch misconfigurations before apply.
DLQ Terraform module

Usage:

1. Set variables in a `terraform.tfvars` file or via CLI/env.

Example `terraform.tfvars`:

```
dlq_bucket_name = "janusec-dlq-bucket-prod"
dlq_queue_name  = "janusec-dlq-queue-prod"
region = "us-east-1"
dlq_retention_days = 90
```

2. Initialize and apply:

```bash
terraform init
terraform apply -var-file=terraform.tfvars
```

The module creates an S3 bucket with KMS server-side encryption, an SQS queue, a KMS key, and an IAM role with a least-privilege policy for DLQ operations. Review the generated IAM policy before applying in production.
