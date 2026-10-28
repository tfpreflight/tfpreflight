# When tfpreflight can't check something

> **In short:** tfpreflight always tells you when it couldn't check something. It never quietly treats it as fine. This page lists the usual reasons, and what you can do about each.

Limits that come from a specific provider are on that provider's page. For AWS (second regions and accounts, calculated regions, `assume_role`, the IAM policy simulator), see [providers/aws/limitations.md](providers/aws/limitations.md).

| Situation | What happens | What you can do |
|---|---|---|
| **No cloud credentials** | It only reads your plan. The cloud checks don't run. | Log in to your cloud provider first, or run it in CI with a role. See [ci.md](ci.md). |
| **The identity can't read your account** | Your cloud provider refuses the questions. Those checks are marked *not checked*. | Give it the read-only permissions for your provider. For AWS: [providers/aws/permissions.md](providers/aws/permissions.md). |
| **Resources from a provider tfpreflight doesn't support yet** | They aren't checked against your cloud, and aren't counted in "Checked N of M resources". Destroy and replace warnings still cover them. | See [providers/README.md](providers/README.md), or [open an issue](https://github.com/tfpreflight/tfpreflight/issues/new/choose) to ask for that provider. |
| **Values Terraform only knows during the apply** (like an ID the provider generates) | That rule is skipped, or marked *not checked*. | Nothing. This is normal. |
| **Your provider version has no exact rules** | Problems show as warnings only. Nothing blocks. | Run `tfpreflight update`. |
| **Terragrunt** | tfpreflight doesn't find Terragrunt projects by itself. | Save a plan with Terragrunt, then run `tfpreflight check --plan=<file>` in the Terraform folder. |
| **Both Terraform and OpenTofu installed** | It picks OpenTofu if your lock file comes from the OpenTofu registry, and Terraform otherwise. | Choose with `--tool terraform` or `--tool tofu`. |
| **Things change after the check** | Someone could take a name or change a permission between the check and the apply. | Run the check close to the apply. |

## About permission checks

A cloud provider's policy simulator can't model everything. tfpreflight follows these rules so it never blocks you by mistake:

- If the simulator **errors**, the permission check is marked *not checked*. It never means "denied".
- A step is only **blocked** when the provider clearly says no **and** nothing else could allow it. Otherwise you get a warning.

The AWS details are in [providers/aws/limitations.md](providers/aws/limitations.md#about-the-iam-policy-simulator).

A clean result means tfpreflight found nothing in what it checked. It's not a promise that the apply will succeed.
