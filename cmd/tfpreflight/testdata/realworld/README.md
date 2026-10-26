# Real-world plans

Saved plans of five [terraform-aws-modules](https://github.com/terraform-aws-modules) examples (Apache-2.0), planned with AWS provider 6.69.1 and Terraform 1.12.0:

| Fixture | Example |
|---|---|
| `vpc-simple` | `terraform-aws-vpc/examples/simple` |
| `s3-complete` | `terraform-aws-s3-bucket/examples/complete` |
| `rds-complete-postgres` | `terraform-aws-rds/examples/complete-postgres` |
| `iam-role` | `terraform-aws-iam/examples/iam-role` |
| `security-group-complete` | `terraform-aws-security-group/examples/complete` |

Each `plan.json` is `terraform show -json` of the plan, keeping only what tfpreflight reads (`prior_state`, drift and checks are dropped). Account IDs are AWS's documentation placeholders and user names are neutral. `main.tf` is the example's provider block and region locals, which is all tfpreflight reads from the configuration. `.terraform.lock.hcl` is the example's lock file.
