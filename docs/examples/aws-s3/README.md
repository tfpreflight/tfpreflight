# Small AWS example

This example creates a Terraform plan without applying it, then runs tfpreflight without real AWS credentials. Use it to see how tfpreflight reports an AWS check that cannot finish.

The example disables the AWS provider's credential and account checks. It points tfpreflight at an address that cannot answer, so tfpreflight has no AWS access for the check.

```sh
terraform init
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  terraform plan -out=tfplan
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_ENDPOINT_URL=http://127.0.0.1:1 AWS_MAX_ATTEMPTS=1 \
  tfpreflight check --plan=tfplan
```

tfpreflight should finish and say that the AWS check was incomplete. It should not claim that a resource is missing or report a blocking result.

For a real project, use its normal provider configuration and AWS credentials instead of these demonstration values.
