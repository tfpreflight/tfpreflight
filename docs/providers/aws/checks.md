# AWS: what tfpreflight checks

> **In short:** for the AWS provider (`hashicorp/aws`), tfpreflight checks permissions with AWS's IAM policy simulator, asks AWS whether names are taken and whether the things your plan points at exist, and checks a short list of AWS service quotas. It only reads from AWS. It never changes anything.

The four kinds of check are explained for any provider in [checks.md](../../checks.md). This page covers the AWS details.

## Versions

tfpreflight has rules for 61 AWS provider versions, from 5.98.0 to 6.70.0, with no rules between 5.100.0 and 6.17.0. On those versions it can block. On any other version it uses the closest rules it has, and only warns. `tfpreflight version` lists them, and `tfpreflight update` downloads rules for newer versions.

## Credentials and calls

tfpreflight uses your normal AWS login, the same one the AWS CLI uses. It loads credentials with the AWS SDK's default chain: environment variables, shared config and credentials files, SSO profiles (after `aws sso login`), `credential_process`, profiles that assume a role, and web identity logins as CI systems use them. Anything else that chain accepts works too. If the provider block names a profile, as plain text, a variable or a local, it uses that profile's credentials instead, as Terraform does. It makes only these calls:

- **Read calls** (Describe, Get, List and similar) to check names, dependencies and quotas.
- **The IAM policy simulator**, to ask whether the identity that will run the apply is allowed to make each call.
- **STS AssumeRole**, only when your provider block assumes a role, so it can look as that role.

None of them changes anything. Calls go only to AWS's official addresses, unless you point the AWS SDK elsewhere yourself (for example with `AWS_ENDPOINT_URL`). The role tfpreflight needs is in [permissions.md](permissions.md).

## 1. Missing permissions

For every step in your plan, tfpreflight asks the IAM policy simulator: *"Is the role that will run the apply allowed to do this?"* By default that's the role your provider block assumes, if it assumes one, or else the identity you're logged in as. `--principal <role ARN>` names a different one.

- Most permission rules come from the provider's source code and aren't yet proven against AWS. When the simulator simply doesn't allow a step on one of those rules, you get a warning, not a block.
- A policy that **explicitly denies** a step is different: no other policy can allow it. It blocks when AWS had everything it needed to decide and the provider always makes that call. Otherwise it's a warning that says why.
- Some AWS resources, like S3 buckets and KMS keys, carry their own access rules (resource-based policies). The simulator doesn't read those. So when one of them *might* allow the step, you get a warning instead of a block.
- Calls whose IAM permission tfpreflight doesn't know are listed under **Not checked** in `--details`.

## 2. Names already taken

Some AWS names must be unique, like IAM role names in your account. S3 bucket names are unique across **all** AWS accounts, so the bucket that has the name may not be yours. tfpreflight asks AWS whether the name is in use before Terraform tries to create it.

If an S3 bucket name belongs to another AWS account, AWS won't say so for sure, so tfpreflight reports *couldn't check*, not a block.

## 3. Things your plan points at that don't exist

For example, a subnet that uses an existing VPC ID. tfpreflight asks AWS whether the VPC exists, and blocks only when AWS clearly answers "not found".

## 4. AWS service quotas

Only these, for now:

| Quota | How it checks | Can it block? |
|---|---|---|
| EC2 vCPUs (Running On-Demand Standard instances) | Only for `aws_instance` resources of the `m6i` family whose instance type is known at plan time. It checks whether **one** instance is bigger than your whole quota. It doesn't add the vCPUs you already use or the other instances in the plan. | Yes |
| Per-region counts: VPCs, customer gateways, VPN connections, VPN concentrators (provider 6.x), launch configurations, AWS Backup plans, AWS Backup vaults | Counts what you already have plus what the plan adds, and compares that with your quota. These rules were generated rather than verified. | No. Going over is reported as couldn't check. |

## What it can't check on AWS

See [limitations.md](limitations.md): second regions and accounts, calculated regions, some `assume_role` setups, and what the policy simulator can't see.
