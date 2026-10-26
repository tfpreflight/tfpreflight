# Privacy

> **In short:** your plan never leaves your machine. tfpreflight only talks to AWS (with your own login), and to our server when you ask it to download new rules. No tracking.

## What stays on your machine

Your plan, your results, account IDs, ARNs, resource names, environment variables and credentials. tfpreflight never uploads any of them.

## What goes over the network

| To | When | What |
|---|---|---|
| AWS | During a check | Normal read-only AWS requests, signed with your own credentials |
| packs.tfpreflight.dev | Only when you run `tfpreflight update` or use `--update` | A normal download request. It doesn't include anything about your project. |

There's no usage tracking and no analytics.

## In CI

If your pipeline saves the JSON report as a CI artifact, that file can contain resource names and IDs. That's your CI system's storage, not ours. Limit who can see it and how long it's kept.