# Changelog

All notable changes to tfpreflight are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0-beta.2 (unreleased)

- Also available as `tfp`, a short name for `tfpreflight`: Homebrew and the install script add it as a link, e.g. `tfp check`.
- Fixed: a provider block with `profile = var.aws_profile` (or a local) no longer makes tfpreflight skip every AWS check. The profile is read the way the region is, and the AWS checks use that profile's credentials, as Terraform does.
- The same variable and local forms now work for `assume_role`'s `role_arn` and `external_id` and for `allowed_account_ids`.
- Fixed: when the profile you chose (`AWS_PROFILE`, or the provider block's `profile`) gives no credentials, the result now says why, in the AWS SDK's words, instead of "no AWS credentials found". An SSO login that has expired or was never done is named with the command that fixes it (`aws sso login --profile <name>`), and a profile that is not in your AWS config is named. Credentials are loaded by the AWS SDK's default chain, as before: SSO, `credential_process`, assume-role and web identity profiles all work, and tests now cover each.

## 0.1.0-beta.1 (2026-10-28)

First public beta. AWS is the first supported provider.

- Checks a Terraform or OpenTofu plan for problems that would make the apply fail, before you run it.
- Checks whether the identity that runs the apply is allowed to make each AWS call the plan needs, using the IAM policy simulator.
- An explicit deny is always shown. It blocks when AWS had everything it needed to decide and the provider always makes that call; otherwise it is a warning that says why.
- Finds names that are already taken, such as S3 buckets and IAM roles.
- Finds things the plan depends on that do not exist, such as a VPC a subnet points at.
- Checks some AWS service limits the plan would go past, such as EC2 vCPUs and VPCs per region.
- Warns about resources the plan destroys or replaces, and values only known during the apply.
- A short default output: one line per problem with what to do about it, and a result line that says how many resources were fully checked. `--details` shows the full report, `--format=json` the same result as JSON.
- Reports each result as blocking, a warning, or couldn't check, and fails only on what it is sure about unless you ask for more. When the AWS checks could not run or got no answer, the result says so and is never shown as a pass.
- Knows 61 AWS provider versions (5.98.0 to 6.70.0) and can block on those; on other versions it only warns. `tfpreflight update` downloads signed rules for newer versions.
- Only reads from AWS, enforced in code, and sends nothing anywhere else. The default output never shows account IDs or full ARNs.
- A `.tfpreflight.yml` settings file and exit codes for CI.
- `tfpreflight check --report` writes a redacted file for reporting a wrong result.
- Installs with Homebrew or a script that checks the download's checksum and, with cosign, its signature.
