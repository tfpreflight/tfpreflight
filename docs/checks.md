# What tfpreflight checks

> **In short:** tfpreflight looks for four kinds of problems that make `terraform apply` stop halfway: missing permissions, names already taken, things your plan points at that don't exist, and limits in your cloud account. It only looks. It never changes anything.

These checks run for resources of the providers tfpreflight supports. AWS is the only one today. For the AWS details (the IAM policy simulator, S3 bucket names, the exact quota list), see [providers/aws/checks.md](providers/aws/checks.md).

## 1. Missing permissions

**The problem.** Terraform creates a few resources, then reaches a step the identity running the apply isn't allowed to do. The apply stops halfway, and you clean up by hand.

**What tfpreflight does.** For every step in your plan where it knows the permission, it asks your cloud provider: *"Is the identity that will run the apply allowed to do this?"* The answer comes from the provider's own policy simulator, not from a guess.

**Good to know.**
- Most permission rules come from the provider's source code and aren't yet proven against the real cloud. When the simulator simply doesn't allow a step on one of those rules, you get a warning, not a block.
- A policy that **explicitly denies** a step is different: no other policy can allow it. It blocks when the provider had everything it needed to decide and Terraform always makes that call. Otherwise it's a warning that says why.
- Some resources carry their own access rules, which the simulator doesn't see. When one of them *might* allow the step, you get a warning instead of a block. (For AWS: S3 bucket policies and KMS key policies.)

## 2. Names already taken

**The problem.** Some names must be unique, in your account or even across every account of the provider. If the name is taken, the apply fails. (For AWS: S3 bucket names are unique across all of AWS.)

**What tfpreflight does.** It asks your cloud provider whether the name is already in use, before Terraform tries to create it.

**Good to know.** If the provider doesn't give a clear answer (no access, a timeout, an odd error), tfpreflight says *couldn't check*. It never guesses.

## 3. Things your plan points at that don't exist

**The problem.** Your plan can point at something that isn't in the plan, like a subnet that uses an existing network ID. If that network doesn't exist (a typo, it was deleted, it's in another account), the apply fails.

**What tfpreflight does.** It asks your cloud provider whether the thing exists.

**Good to know.** It only blocks when the provider clearly answers "not found".

## 4. Limits (quotas)

**The problem.** Cloud accounts have limits, like how many networks you can have in a region. Going over one makes the apply fail.

**What tfpreflight checks today.** Only a short list of AWS quotas. The list, and which of them can block, is in [providers/aws/checks.md](providers/aws/checks.md#4-aws-service-quotas).

## 5. Risky changes

These come from the plan alone, so they cover every resource, whatever its provider:

- a **warning** for each resource the plan destroys or replaces;
- a minor note (shown with `--all`) for each resource with values Terraform will only know during the apply, which some checks can't use.

## Why some results are only warnings

tfpreflight has rules made for exact provider versions. If your project uses one of those exact versions, a problem can **block** the run. If not, tfpreflight uses the closest rules it has, and every problem it finds is shown as a **warning** only.

- `tfpreflight version` shows which versions your rules cover.
- `tfpreflight update` downloads rules for newer versions.

## What a clean result means

tfpreflight found no problem in the things it checked. It's not a promise that the apply will succeed: your cloud provider can still reject a step for a reason no tool can see in advance, and things can change between the check and the apply.
