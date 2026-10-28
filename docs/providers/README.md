# Providers

> **In short:** tfpreflight checks the resources of the Terraform providers it has rules for. AWS is the only one today. More are coming; [open an issue](https://github.com/tfpreflight/tfpreflight/issues/new/choose) to tell us which one you need.

| Provider | Status | Docs |
|---|---|---|
| AWS (`hashicorp/aws`) | Available now | [AWS checks](aws/checks.md), [AWS permissions](aws/permissions.md), [AWS limitations](aws/limitations.md) |
| Others | Not supported yet. [Open an issue](https://github.com/tfpreflight/tfpreflight/issues/new/choose) to request one. | |

## What "provider support" means

For a supported provider, tfpreflight has **rules for exact provider versions**. The rules for a version say which calls each resource makes, which permission each call needs, which names must be unique, what a resource depends on, and which limits it uses. They are built from that version's own source code, and some are proven by running the real calls in a test account.

- On a version it has rules for, tfpreflight can block.
- On any other version of a supported provider, it uses the rules of the closest version it knows, and only warns.
- `tfpreflight version` lists the versions it has rules for. `tfpreflight update` downloads rules for newer ones. See [updates.md](../updates.md).

## Resources from other providers

A plan can mix providers. Resources from a provider tfpreflight doesn't support yet aren't checked against your cloud and aren't counted in "Checked N of M resources". tfpreflight still warns when the plan destroys or replaces them, because that warning comes from the plan alone.
