# Provider profile from a variable

A plan whose provider block sets `profile = var.aws_profile` and `region = var.aws_region`. The plan records both only as what they reference (`{"references": ["var.aws_profile"]}`) and puts the values in `variables`. tfpreflight reads the profile and region the same way, and loads its AWS credentials from that profile.

Unlike the plans in `../realworld`, this one is not from a public example. It is the plan of the small configuration in `main.tf`, made offline with Terraform 1.12.0 and AWS provider 6.64.0, and `plan.json` is `terraform show -json` of it, minus the `timestamp`. To make it again:

```sh
# aws-config holds [profile example] with any access keys; nothing is called.
AWS_CONFIG_FILE=aws-config AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  terraform init -plugin-dir=<a folder holding registry.terraform.io/hashicorp/aws/6.64.0>
AWS_CONFIG_FILE=aws-config AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  terraform plan -var aws_region=eu-west-1 -var aws_profile=example -out=tfplan
terraform show -json tfplan
```

`skip_credentials_validation`, `skip_metadata_api_check` and `skip_requesting_account_id` keep the plan from calling AWS. `.terraform.lock.hcl` is what `terraform init` wrote.
