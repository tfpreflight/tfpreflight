# The AWS permissions tfpreflight needs

> **In short:** tfpreflight needs an AWS role that can **read** your account. We give you a ready-made policy. Create a role, attach the policy, and you're done. Nothing in it can change your infrastructure.

## Set it up in 3 steps

1. **Create a role just for tfpreflight**, for example `tfpreflight-reader`. In CI, let your CI system log into it with a short-lived login (OIDC) instead of storing AWS keys. See [ci.md](ci.md).
2. **Attach the policy.** Copy [tfpreflight-iam-policy.json](tfpreflight-iam-policy.json) and add it to the role as an **inline** policy.
   - Why inline? The policy is about 9,600 characters. Inline policies allow up to 10,240 characters. Managed policies only allow 6,144, so it doesn't fit in one. If your company requires managed policies, split it into two.
3. **Only if your AWS provider uses `assume_role`:** add the extra statement below.

## What the policy allows

It has two parts:

| Part | What it allows | Why |
|---|---|---|
| `ReadOnlyInspection` | About 310 **read** actions (Describe, Get, List and similar) | To check names, dependencies and limits |
| `PermissionSimulation` | 2 IAM actions that **ask** whether a role is allowed to do something | To check the permissions of the role that will run the apply |

Nothing in the policy can create, change, or delete anything.

**If a permission is missing,** that part of the check is marked *not checked*. It never turns into a false block.

## If your provider uses `assume_role`

tfpreflight logs in as the same role your Terraform provider uses. Allow that with this statement, replacing both placeholders:

```json
{
  "Sid": "AssumeTerraformProviderRole",
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<DEPLOY_ROLE_NAME>"
}
```

Keep `Resource` set to that one role, never `*`. The deploy role must also trust your tfpreflight role.

## Tightening it

- The policy uses `"Resource": "*"`, because many AWS read actions can't be limited to one resource. Where AWS allows it, you can narrow it.
- You can remove services your projects never use.
- In `PermissionSimulation`, if you always apply with one role, replace the wildcards with that role's ARN.

## Small details

- Some AWS permission names don't match the action they allow. For example, API Gateway reads need `apigateway:GET`, and checking an S3 bucket needs `s3:ListBucket`. The policy already handles this.
- The policy doesn't include `sts:GetCallerIdentity` (the "who am I" call). AWS always allows it.
- Check this policy again when you upgrade tfpreflight. New checks may need new read permissions.