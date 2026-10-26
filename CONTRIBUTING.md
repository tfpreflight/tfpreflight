# Contributing

Bug fixes, tests, documentation and runtime improvements are welcome. Keep each pull request focused on one change.

The rules (the pack files under `packs/aws/`) are built outside this repository and published as signed bundles; those files are not edited by hand. To report a wrong or missing result, attach a support bundle from `tfpreflight check --report <path>`, as described in [docs/reporting.md](docs/reporting.md).

## Before you open a pull request

Run these from the repository root. All of them must pass:

```sh
gofumpt -l .                       # prints nothing
golangci-lint run ./...            # 0 issues
GOWORK=off go vet ./...
GOWORK=off go build ./...
GOWORK=off go test -race -timeout 20m ./...
```

`go test -short ./...` skips the tests that materialize every shipped provider version, for a quick loop while you work.

## Code style

[Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) are the baseline. On top of them:

- **Comments** explain why: a constraint, an invariant, a rejected alternative. They do not restate the next line, and they carry no history ("added in", "now", "legacy"). Every package and exported identifier has a short doc comment that starts with its name.
- **Errors** are wrapped with `%w` and enough context to locate the failure. Keep the cause.
- **Names** say what the value is; avoid `data`, `result`, `info`, `manager`, `util` and `helper`. Export only what another package needs.
- **Interfaces** exist when there are two implementations, or a test must substitute one.
- **Tests** are table-driven where cases share a shape, and assert the contract: findings, coverage, exit codes, JSON fields and output text, not internal formatting.
- **Never** place real AWS account IDs, credentials, ARNs or resource names in fixtures.

## Rules the runtime keeps

- Nothing blocks without verified evidence.
- A check that could not finish is PARTIAL: never a failure, and never "missing".
- tfpreflight only reads AWS. Lookup specs are held to that in code (`rules/readonly.go`).
- Pack downloads keep their signature and hash checks, across redirects too.
