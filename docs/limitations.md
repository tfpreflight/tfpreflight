# When tfpreflight can't check something

> **In short:** tfpreflight always tells you when it couldn't check something. It never quietly treats it as fine. This page lists the usual reasons, and what you can do about each.

| Situation | What happens | What you can do |
|---|---|---|
| **No AWS credentials** | It only reads your plan. AWS checks don't run. | Log in to AWS first, or run it in CI with a role. See [ci.md](ci.md). |
| **The role can't read your account** | AWS refuses the questions. Those checks are marked *not checked*. | Give the role the [read-only policy](aws-permissions.md). |
| **Resources in a second region or account** (a provider `alias` like `aws.west`, or a module with its own `provider "aws"` block) | Those resources aren't checked against AWS. tfpreflight checks one account and region per run: your main AWS provider. | Run a separate check for that account and region. |
| **The region is calculated** (with a function, a condition, or a local that depends on other values) | AWS checks don't run, because tfpreflight doesn't know where to look. | Write the region as plain text, a root variable, or a plain local, or set `AWS_REGION`. |
| **`assume_role` with a calculated role ARN**, or with a session policy | AWS checks don't run. | Use a plain role ARN or a root variable. |
| **`assume_role_with_web_identity` in the provider block** | tfpreflight can't copy that login. | Log in through the environment instead. CI OIDC logins work. |
| **Access keys, custom endpoints, or credential-file settings written in the provider block** | tfpreflight ignores them and uses your normal AWS login. | Use your normal AWS environment or profile. |
| **Values Terraform only knows during the apply** (like an ID AWS generates) | That rule is skipped, or marked *not checked*. | Nothing. This is normal. |
| **Your AWS provider version has no exact rules** | Problems show as warnings only. Nothing blocks. | Run `tfpreflight update`. |
| **An S3 bucket policy or KMS key policy might allow a step** | tfpreflight doesn't read those policies, so it warns instead of blocking. | Check that policy yourself. |
| **Terragrunt** | tfpreflight doesn't find Terragrunt projects by itself. | Save a plan with Terragrunt, then run `tfpreflight check --plan=<file>` in the Terraform folder. |
| **Both Terraform and OpenTofu installed** | It picks OpenTofu if your lock file comes from the OpenTofu registry, and Terraform otherwise. | Choose with `--tool terraform` or `--tool tofu`. |
| **Things change after the check** | Someone could take a name or change a permission between the check and the apply. | Run the check close to the apply. |

## About permission checks

AWS's permission tool can't model everything: some organisation-wide rules and run-time conditions aren't included. tfpreflight follows two rules so it never blocks you by mistake:

- If AWS's tool **errors**, the permission check is marked *not checked*. It never means "denied".
- A step is only **blocked** when AWS clearly says no **and** nothing else (like a bucket or key policy) could allow it. Otherwise you get a warning.
- A policy that **explicitly denies** a step is always shown, even when the resource's ID isn't known until the apply. It blocks only when AWS had every value it needed to decide and tfpreflight's rules say Terraform always makes that call. Otherwise it's a warning that says why.

A clean result means tfpreflight found nothing in what it checked. It's not a promise that the apply will succeed.
