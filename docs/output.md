# Reading the result

> **In short:** by default you get one header line, one short entry per problem, and a result line. `✗` means the apply will likely fail, `!` means something needs your attention or couldn't be checked, and `✓` means nothing was found. `--details` shows everything else.

## The default output

```
tfpreflight · AWS provider 6.64.0 · us-east-1 · 6 resources

FAIL  aws_s3_bucket.logs
      Bucket name "acme-logs" is already taken.
      Fix: use a different name, or import the existing bucket.

FAIL  aws_security_group.web
      The apply role is not allowed to run ec2:CreateSecurityGroup.
      Fix: remove or narrow the deny on role "deploy".

WARN  aws_s3_bucket_public_access_block.logs
      The apply role may not be allowed to run s3:PutBucketPublicAccessBlock.
      Check: this rule comes from the provider's source and is not yet verified against AWS.

✗ 2 problems will likely make apply fail. 1 warning.
  Checked 4 of 6 resources fully. Details: tfpreflight check --details
```

- **The header** names the AWS provider version, the region tfpreflight checked (`region unknown` if it couldn't work one out), and how many AWS resources the plan changes.
- **Each entry** is `FAIL` or `WARN`, the resource's address, one sentence saying what's wrong, and one line saying what to do: `Fix:` when the fix is clear, `Check:` when you need to confirm something first.
- **The result line** sums it up (see below). "Checked N of M resources fully" counts resources where every check that applies to them finished. A resource with even one check that couldn't finish doesn't count. A check with nothing to check doesn't stop it counting: a dependency check that found no rule for the resource, or a quota check for a resource type tfpreflight knows no quota for. So "fully" means every check tfpreflight has a rule for finished, not that no quota or dependency could exist.

The default output never shows account IDs or full ARNs. A role is named as `role "deploy"`, and any ARN inside a message is cut to its last part, such as `role/deploy`.

## The two kinds of entry

| You see | What it means | What to do | Fails the run by default? |
|---|---|---|---|
| **FAIL** | tfpreflight is sure enough that the apply will fail at this step. | Fix it before you apply. | Yes (exit code `1`) |
| **WARN** | Probably a problem, but not sure enough to stop you. | Do what the `Check:` or `Fix:` line says before you apply. | No |

Minor notes (informational findings) aren't listed. `--all` shows them, together with the full output.

## The result line

| Result line | Meaning |
|---|---|
| `✗ N problems will likely make apply fail.` | At least one blocking problem. Fix it before you apply. Warnings, if any, are counted on the same line. |
| `! N warnings to check. Nothing found that is sure to make apply fail.` | Only warnings. Read them before you apply. |
| `✓ No problems found. Checked N of M resources fully.` | Nothing was found. If some resources couldn't be fully checked, a second line says how many. |
| `! AWS checks did not run: <reason>.` | tfpreflight only read your plan, for example because there are no AWS credentials or the region is unknown. The next line says what to do. |
| `! AWS checks failed: <reason>.` | tfpreflight reached AWS, but AWS refused or failed every question, usually because the role is missing read permissions. |
| `! Nothing was checked in AWS.` | Only checks that read the plan finished. |
| `! Nothing could be checked.` | No check finished for any resource. |

If your `--fail-on` or `--fail-on-partial` setting is what makes the run exit `1`, a last line says so, for example `Exits 1 because --fail-on warning is set.`

If your AWS provider version has no rules of its own, a line under the header says which rules were used and that results are warnings only, for example `Rules for 6.69.1 are newest; results are warnings only. Run: tfpreflight update`.

## The full output (`--details`)

`tfpreflight check --details` prints the full report: the provider and policy lines, the region and both identities (the one that inspects AWS and the one whose permissions are checked), every finding with what Terraform is doing, the problem, what it means and the fix, a **Not checked** list, coverage counts per check, and a last line starting `Preflight:`:

| Last line | Meaning |
|---|---|
| `Preflight: FAILED` | At least one blocking problem. Fix it before you apply. |
| `Preflight: FAILED (<reason>)` | Your `--fail-on` or `--fail-on-partial` setting made a warning or incomplete check fail the run. |
| `Preflight: PASSED (PARTIAL)` | Nothing was found, but some checks couldn't finish. Look at **Not checked**. |
| `Preflight: PARTIAL - AWS checks did not run: <reason>` | tfpreflight only read your plan. It couldn't talk to AWS, usually because of missing credentials or an unknown region. |
| `Preflight: PARTIAL - AWS checks failed: <reason>` | tfpreflight reached AWS, but AWS refused or failed every question, usually because the role is missing read permissions. |
| `Preflight: PARTIAL - nothing was verified` | No check completed for any resource. |
| `Preflight: PARTIAL - nothing was checked in AWS` | Only checks that read the plan completed. AWS did not answer any check. |
| `Preflight: COMPLETE` | Every applicable check completed and nothing met your failure rule. |

Under it are two count lines: how many findings of each kind, and how many resources were fully checked, partly checked, or not covered. "Fully checked" means the same as in the default output. The JSON output has the same verdict and counts.

## The version label

The full output's first lines name your AWS provider version and one of these labels:

| Label | Meaning |
|---|---|
| **COVERED** | tfpreflight has rules for exactly this version. Problems can block. |
| **NEWER** | Your version is newer than the rules. It uses its newest rules, and problems are warnings only. Run `tfpreflight update`. |
| **OLDER** | Your version is older than the rules. It uses its oldest rules, and problems are warnings only. |
| **GAP** | There are no rules for your version, but there are for versions on both sides. It uses the closest older rules, and problems are warnings only. |

tfpreflight uses `--provider-version` first, then `provider_version` in `.tfpreflight.yml`, then `.terraform.lock.hcl`.

## Making it stricter

By default, only blocking problems fail the run. You can make it stricter:

| Setting | Effect |
|---|---|
| `--fail-on warning` | Warnings fail the run too. |
| `--fail-on-partial` | Checks that couldn't finish fail the run too. **Recommended in CI**, so expired credentials can't let every change pass. |

Or save them in a `.tfpreflight.yml` file next to your Terraform files:

```yaml
provider_version: 6.64.0   # optional: use this version instead of the lock file's
fail_on: warning           # "error" (the default) or "warning"
fail_on_partial: true      # true or false
```

Only these three settings exist. A typo or a wrong value (like `yes` instead of `true`) is an error, and tfpreflight tells you which line. Command-line flags win over the file.

## JSON output

Add `--format=json` to get the result as JSON, for scripts and CI. The totals are in `summary`: `verdict`, `blocking`, `non_blocking`, `warnings`, `informational`, `checked`, `partial`, `not_covered` and `unsupported`.

`--debug` prints extra detail for troubleshooting. It goes to stderr, so it never mixes into the JSON.
