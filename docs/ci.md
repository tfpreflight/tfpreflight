# Running tfpreflight in CI

> **In short:** run `tfpreflight check` right after `terraform plan` in your pipeline. If it finds a blocking problem, the job fails and the change doesn't get applied. Two copy-paste examples below: GitHub Actions and GitLab CI.

## Before you start

1. **Create a read-only AWS role** for tfpreflight. See [aws-permissions.md](aws-permissions.md).
2. **Let your CI log into that role with OIDC.** OIDC is a short-lived login your CI system gets automatically, so you never store AWS keys as CI secrets.
3. **Add this file** next to your Terraform files:

   ```yaml
   # .tfpreflight.yml
   fail_on_partial: true
   ```

   Why: without it, a job with expired credentials or missing permissions would check nothing and still pass. With it, the job fails when checks can't finish.

## GitHub Actions

Replace the role ARN with your tfpreflight role. In AWS, set the role's trust policy so only this repository (and the branches you choose) can log in.

```yaml
name: terraform-preflight
on: [pull_request]
permissions:
  contents: read
  id-token: write   # lets the job get an OIDC login
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::<AWS_ACCOUNT_ID>:role/tfpreflight-ci
          aws-region: us-east-1
      - name: Install tfpreflight
        run: curl -fsSL https://get.tfpreflight.dev/install.sh | sh
      - name: Plan and check
        run: |
          terraform init -input=false
          terraform plan -input=false -out=tfplan
          tfpreflight check --plan=tfplan --format=json > tfpreflight.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: tfpreflight-report
          path: tfpreflight.json
```

For production, pin each `uses:` action to a commit SHA instead of a version tag.

## GitLab CI

Set the CI variable `TFPREFLIGHT_ROLE_ARN` to your tfpreflight role. In AWS, set the role's trust policy to accept GitLab's OIDC login, limited to your project and the branches or tags you choose.

```yaml
preflight:
  image: hashicorp/terraform:light
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: sts.amazonaws.com
  before_script:
    - apk add --no-cache aws-cli curl jq
    - >-
      CREDS="$(aws sts assume-role-with-web-identity
      --role-arn "$TFPREFLIGHT_ROLE_ARN"
      --role-session-name "gitlab-${CI_PIPELINE_ID}"
      --web-identity-token "$GITLAB_OIDC_TOKEN"
      --duration-seconds 3600)"
    - export AWS_ACCESS_KEY_ID="$(printf '%s' "$CREDS" | jq -r .Credentials.AccessKeyId)"
    - export AWS_SECRET_ACCESS_KEY="$(printf '%s' "$CREDS" | jq -r .Credentials.SecretAccessKey)"
    - export AWS_SESSION_TOKEN="$(printf '%s' "$CREDS" | jq -r .Credentials.SessionToken)"
    - curl -fsSL https://get.tfpreflight.dev/install.sh | sh
  script:
    - terraform init -input=false
    - terraform plan -input=false -out=tfplan
    - tfpreflight check --plan=tfplan --format=json > tfpreflight.json
  artifacts:
    when: always
    paths: [tfpreflight.json]
```

## Two rules

- **Don't add `|| true`** after the check command. Its exit code is what should pass or fail the job.
- **Keep the JSON report private.** It can contain resource names and IDs, so limit who can see your CI artifacts and how long they're kept.

`--principal` is optional. It names the role that will run the apply, if that's different from the one tfpreflight logs in as.