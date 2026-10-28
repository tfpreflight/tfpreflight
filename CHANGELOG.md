# Changelog

All notable changes to tfpreflight are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## 0.1.0-beta.1 (unreleased)

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
