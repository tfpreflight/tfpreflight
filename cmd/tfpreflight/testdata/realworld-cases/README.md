# Real-world cases

Plans written from a real failed apply, kept small so the case is easy to read. Each directory holds `plan.json`, the provider block in `main.tf` and the lock file; the account and group IDs are the placeholders AWS uses in its documentation.

| Case | What happened |
|---|---|
| `sg-ingress-literal-peer` | `aws_vpc_security_group_ingress_rule` with `referenced_security_group_id = "sg-0123456789abcdef0"` (a group that does not exist). Terraform's apply failed with `InvalidGroup.NotFound` from `AuthorizeSecurityGroupIngress`. tfpreflight with provider 6.70.0 found nothing, because the packs have no knowledge of this resource. |
| `instance-in-missing-subnet` | `aws_instance` with `subnet_id = "subnet-0a1b2c3d4e5f60718"` (a subnet that does not exist). Terraform's apply failed in `RunInstances`. Used to check that a clean result never reads as everything having been checked. |
| `log-stream-no-checks` | `aws_cloudwatch_log_stream`, a resource the packs have only permission rules for. Used to check the permissions-only wording. Not from a failed apply. |
