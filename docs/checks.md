# What tfpreflight checks

> **In short:** tfpreflight looks for four kinds of problems that make `terraform apply` stop halfway: missing permissions, names already taken, things your plan points at that don't exist, and AWS limits. It only looks. It never changes anything.

AWS is the first supported provider. Everything on this page is about AWS.

## 1. Missing permissions

**The problem.** Terraform creates a few resources, then reaches a step the role isn't allowed to do. The apply stops halfway, and you clean up by hand.

**What tfpreflight does.** For every step in your plan, it asks AWS: *"Is the role that will run the apply allowed to do this?"* AWS has a built-in tool for exactly this question (the IAM policy simulator), so the answer comes from AWS itself.

**Good to know.**
- Most permission rules come from the provider's source code and aren't yet proven against AWS. When AWS simply doesn't allow a step on one of those rules, you get a warning, not a block.
- A policy that **explicitly denies** a step is different: no other policy can allow it. It blocks when AWS had everything it needed to decide and the provider always makes that call; otherwise it's a warning that says why.
- Some AWS resources, like S3 buckets and KMS keys, can carry their own access rules. tfpreflight doesn't read those. So when one of them *might* allow the step, you get a warning instead of a block.

## 2. Names already taken

**The problem.** Some names must be unique. S3 bucket names, for example, are unique across all of AWS. If the name is taken, the apply fails.

**What tfpreflight does.** It asks AWS whether the name is already in use, before Terraform tries to create it.

**Good to know.** If AWS doesn't give a clear answer (no access, a timeout, an odd error), tfpreflight says *couldn't check*. It never guesses.

## 3. Things your plan points at that don't exist

**The problem.** Your plan can point at something that isn't in the plan, like a subnet that uses an existing VPC ID. If that VPC doesn't exist (a typo, it was deleted, it's in another account), the apply fails.

**What tfpreflight does.** It asks AWS whether the thing exists.

**Good to know.** It only blocks when AWS clearly answers "not found".

## 4. AWS limits (quotas)

**The problem.** Every AWS account has limits, like how many VPCs you can have in a region. Going over one makes the apply fail.

**What tfpreflight checks today.** Only these, for now:

| Limit | How it checks | Can it block? |
|---|---|---|
| EC2 vCPUs (On-Demand Standard) | Only for `m6i` instances with a known size. It checks whether **one** instance is bigger than your whole limit. It doesn't add up instances you already run. | Yes |
| Per-region counts: VPCs, customer gateways, VPN connections, VPN concentrators (provider 6.x), launch configurations, AWS Backup plans, AWS Backup vaults | Counts what you already have plus what the plan adds, and compares that with your limit. | No, it reports that the quota could not be checked |

## Why some results are only warnings

tfpreflight has rules made for exact AWS provider versions. If your project uses one of those exact versions, a problem can **block** the run. If not, tfpreflight uses the closest rules it has, and every problem it finds is shown as a **warning** only.

- `tfpreflight version` shows which versions your rules cover.
- `tfpreflight update` downloads rules for newer versions.

## What a clean result means

tfpreflight found no problem in the things it checked. It's not a promise that the apply will succeed: AWS can still reject a step for a reason no tool can see in advance, and things can change between the check and the apply.
