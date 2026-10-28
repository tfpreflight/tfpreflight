# AWS: when tfpreflight can't check something

> **In short:** on AWS, tfpreflight checks one account and one region per run, and it needs to know which ones from your provider block. When it can't work that out, or can't log in the way Terraform does, it says so and doesn't check. It never treats that as fine.

General limits that apply to any provider are in [limitations.md](../../limitations.md).

| Situation | What happens | What you can do |
|---|---|---|
| **No AWS credentials** | It only reads your plan. AWS checks don't run. | Log in to AWS first, or run it in CI with a role. See [ci.md](../../ci.md). |
| **The role can't read your account** | AWS refuses the questions. Those checks are marked *not checked*. | Give the role the [read-only policy](permissions.md). |
| **Resources in a second region or account** (a provider `alias` like `aws.west`, or a module with its own `provider "aws"` block) | Those resources aren't checked against AWS. tfpreflight checks one account and region per run: your main AWS provider. | Run a separate check for that account and region. |
| **The region is calculated** (with a function, a condition, or a local that depends on other values) | AWS checks don't run, because tfpreflight doesn't know where to look. | Write the region as plain text, a root variable, or a plain local, or set `AWS_REGION`. |
| **`assume_role` with a calculated role ARN**, or with a session policy | AWS checks don't run. | Use a plain role ARN or a root variable. |
| **`assume_role_with_web_identity` in the provider block** | tfpreflight can't copy that login. | Log in through the environment instead. CI OIDC logins work. |
| **Access keys, custom endpoints, or credential-file settings written in the provider block** | tfpreflight ignores them and uses your normal AWS login. | Use your normal AWS environment or profile. |
| **An S3 bucket policy or KMS key policy might allow a step** | tfpreflight doesn't read those policies, so it warns instead of blocking. | Check that policy yourself. |

## About the IAM policy simulator

AWS's policy simulator can't model everything: some organisation-wide rules and run-time conditions aren't included. tfpreflight follows these rules so it never blocks you by mistake:

- If the simulator **errors**, the permission check is marked *not checked*. It never means "denied".
- A step is only **blocked** when AWS clearly says no **and** nothing else (like a bucket or key policy) could allow it. Otherwise you get a warning.
- A policy that **explicitly denies** a step is always shown, even when the resource's ID isn't known until the apply. It blocks only when AWS had every value it needed to decide and tfpreflight's rules say Terraform always makes that call. Otherwise it's a warning that says why.
