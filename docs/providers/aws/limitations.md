# AWS: when tfpreflight can't check something

> **In short:** on AWS, tfpreflight checks one account and one region per run, and it needs to know which ones from your provider block. When it can't work that out, or can't log in the way Terraform does, it says so and doesn't check. It never treats that as fine.

General limits that apply to any provider are in [limitations.md](../../limitations.md).

| Situation | What happens | What you can do |
|---|---|---|
| **No AWS credentials** | It only reads your plan. AWS checks don't run. | Log in to AWS first, or run it in CI with a role. See [ci.md](../../ci.md). |
| **The profile you chose has no usable credentials** (`AWS_PROFILE`, or the provider block's `profile`), for example an SSO login that has expired | AWS checks don't run. The result names the profile and says why, in the AWS SDK's words. | For SSO, run `aws sso login --profile <name>` and run tfpreflight again. Otherwise fix what the reason says. |
| **The profile you chose isn't in your AWS config** | AWS checks don't run. The result names the profile. | Define it in your AWS config (`~/.aws/config`), or correct `AWS_PROFILE`. |
| **The role can't read your account** | AWS refuses the questions. Those checks are marked *not checked*. | Give the role the [read-only policy](permissions.md). |
| **Resources in a second region or account** (a provider `alias` like `aws.west`, or a module with its own `provider "aws"` block) | Those resources aren't checked against AWS. tfpreflight checks one account and region per run: your main AWS provider. | Run a separate check for that account and region. |
| **The region is calculated** (with a function, a condition, or a local that depends on other values) | AWS checks don't run, because tfpreflight doesn't know where to look. | Write the region as plain text, a root variable, or a plain local, or set `AWS_REGION`. |
| **The provider's `profile` is calculated**, or the profile isn't in your AWS config | AWS checks don't run, because tfpreflight can't tell which credentials Terraform uses. | Write the profile as plain text, a root variable or a plain local, and define it in your AWS config. |
| **`allowed_account_ids` is calculated** | AWS checks don't run, because tfpreflight can't tell which accounts the provider allows. | Write the list as plain text, a root variable that holds a list, or a list of plain text, variables and plain locals. |
| **`assume_role` with a calculated role ARN** | tfpreflight can't name the role. The name, dependency and quota checks don't run, and permissions are checked only if you pass `--principal`. | Write the role ARN as plain text, a root variable or a plain local, or pass the role with `--principal`. |
| **`assume_role` with a calculated external ID** | tfpreflight can't assume the role to look as it. The name, dependency and quota checks don't run. Permissions are still checked. | Write the external ID as plain text, a root variable or a plain local. |
| **`assume_role` with a session policy** | Permissions are checked for the role alone, which allows at least as much as the session. The report says so. | Nothing. |
| **`assume_role_with_web_identity` in the provider block** | AWS checks don't run, because tfpreflight can't copy that login. | Log in through the environment instead. CI OIDC logins work. |
| **Access keys, a token, custom endpoints, or credential-file settings written in the provider block** (`access_key`, `secret_key`, `token`, `endpoints`, `shared_config_files`, `shared_credentials_files`, `forbidden_account_ids`) | AWS checks don't run, because tfpreflight can't rebuild that login. A variable instead of plain text makes no difference. | Use your normal AWS environment or a profile. |
| **An S3 bucket policy or KMS key policy might allow a step** | tfpreflight doesn't read those policies, so it warns instead of blocking. | Check that policy yourself. |

## Provider settings that can be a variable

tfpreflight reads these provider settings from your plan and from the provider block. Each can be written as plain text, as a root variable on its own (`var.name`, using the value the plan records), or as a local set to plain text. A function, a condition, or anything built from other values can't be resolved.

| Setting | Notes |
|---|---|
| `region` | |
| `profile` | tfpreflight uses that profile's credentials, as Terraform does, and not the environment's. A variable the plan records as null or empty means no profile. |
| `assume_role` `role_arn` | |
| `assume_role` `external_id` | Never shown in the output. |
| `allowed_account_ids` | A list variable, a list of plain text, variables and plain locals, or a local set to a list of plain text. |

## About the IAM policy simulator

AWS's policy simulator can't model everything: some organisation-wide rules and run-time conditions aren't included. tfpreflight follows these rules so it never blocks you by mistake:

- If the simulator **errors**, the permission check is marked *not checked*. It never means "denied".
- A step is only **blocked** when AWS clearly says no **and** nothing else (like a bucket or key policy) could allow it. Otherwise you get a warning.
- A policy that **explicitly denies** a step is always shown, even when the resource's ID isn't known until the apply. It blocks only when AWS had every value it needed to decide and tfpreflight's rules say Terraform always makes that call. Otherwise it's a warning that says why.
