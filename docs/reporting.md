# Reporting a wrong result

> **In short:** if tfpreflight got something wrong, run the same check with `--report`. It makes a file with the details we need, and your private information removed. Attach it to a GitHub issue.

## Which issue to open

- **Wrong result** template: a false warning, a false block, or a problem it missed.
- **Bug** template: a crash, an install problem, or anything else broken.

## Make the report

```sh
tfpreflight check --plan=tfplan --report=tfpreflight-report.json
```

It also prints the whole report on screen. **Read it before you share it.** The file is saved so only you can read it.

**What's in it:** the tfpreflight version, your AWS provider version, the rules version, and the findings, with private details removed.

**What's taken out:** plan values, account IDs, ARNs, resource names, region and account details, file paths, free-text messages, and raw error messages. Resource names become labels like `resource-001`, so we can still match findings to each other without seeing your real names.

## If we ask for more detail

Sometimes we need the real names to understand the problem. Only if you're comfortable sharing them:

```sh
tfpreflight check --plan=tfplan \
  --report=tfpreflight-report-full.json \
  --report-include-sensitive
```

This version **keeps** account IDs, ARNs, resource names and paths. Read it before you share it.

Neither report ever includes your plan file or your AWS credentials.