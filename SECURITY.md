# Security policy

tfpreflight reads Terraform plans, uses AWS credentials through the AWS SDK's standard chain, makes signed AWS API calls, and downloads signed rules. Please report security problems privately, not in a public issue.

## Reporting a vulnerability

Use either:

- GitHub private vulnerability reporting: [report a vulnerability](https://github.com/tfpreflight/tfpreflight/security/advisories/new).
- Email: [hello@tfpreflight.dev](mailto:hello@tfpreflight.dev), with "security" in the subject.

Include the tfpreflight version (`tfpreflight version`), your operating system, what you found, and how to reproduce it. Do not send real credentials, account IDs, ARNs, plans, or support bundles from production systems; a minimal reproduction is enough.

## Scope

In scope:

- the `tfpreflight` CLI and everything under `cmd/`, `internal/`, `rules/` and `packs/`;
- the installer (`install.sh`) and the release artifacts: archives, checksums and their signatures;
- rule downloads, their signature and hash verification, and the rules cache;
- handling of plans, AWS credentials and identities, and support bundles, including anything that leaks them.

Out of scope:

- vulnerabilities in Terraform, OpenTofu, the AWS SDK or AWS itself; report those to their maintainers;
- a wrong check result with no security impact; use the [wrong result](https://github.com/tfpreflight/tfpreflight/issues/new?template=wrong-result.yml) issue form.

## What to expect

- We acknowledge a report within 3 business days.
- We give an initial assessment, including whether we accept it as a vulnerability, within 10 business days.
- We aim to release a fix within 90 days of the report, sooner for severe issues, and keep you informed until then.
- We publish a GitHub security advisory with the fix and credit you unless you ask us not to.

Please give us that time before disclosing publicly.

## Supported versions

During the beta, only the latest release receives security fixes. Upgrade with the [installer](docs/install.md) or `brew upgrade tfpreflight`.
