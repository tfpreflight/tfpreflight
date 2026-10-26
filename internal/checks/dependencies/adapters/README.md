# Dependency lookup adapters

This package answers one question for the dependency check: does the AWS object
with this identifier exist? The check uses it to tell whether a resource the plan
references, such as a subnet's VPC, is really there before apply.

## Where the answer comes from

`New` builds a `Registry` for one AWS provider version:

- the version's dependency rules come from the embedded packs (`Rules`);
- a lookup that has a spec (`Specs`, from `aws/lookup/`) goes through the generic
  engine in `internal/awscall`;
- the few lookups without a spec use the generated SDK clients in
  `zz_generated_adapters.go`. Do not edit that file by hand.

A spec and its rules must agree on what proves absence, or the registry refuses
to start. So does a release binary whose linked AWS SDK service modules differ
from the versions the generated adapters were built against (`sdkVersions`).
When the registry cannot start, every lookup answers `Unknown` with the reason.

## What the answers mean

- `Exists`: AWS returned the object.
- `NotFound`: AWS returned the lookup's own not-found error code or type.
  Nothing else proves absence.
- `Unknown`: everything else, including AccessDenied, throttling, timeouts,
  cancellation, an unregistered lookup and a reply that does not clearly say.
  It is never read as missing.

## Behaviour

- Each question (scope, lookup and identifier) is asked at most once per run.
  The answer is cached, and a second caller waits for an identical lookup
  already in flight.
- At most 8 lookups run at once (`maxConcurrentLookups`), and each has a
  15-second limit (`lookupTimeout`).
- `Prefetch` resolves lookups ahead of evaluation. It only saves time; the
  verdicts are the same without it.
- This package does not decide where to look. Account, region, provider alias
  and scope checks happen in `internal/aws` before a lookup reaches it, and
  whether a missing target blocks is decided in `internal/checks/dependencies`.

## Tests

Tests use fake HTTP responses. `testdata/` pins, for provider 6.64.0, each
lookup's expected state and the SDK modules the generated adapters use. The tests
make no real AWS calls.
