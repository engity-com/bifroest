# Offline CLI checks

Developer checks for the real `bifroest test` command and native/container parity.
To write configuration tests, use the [guide](../../docs/guides/testing.md),
[reference](../../docs/reference/testing/index.md) and [examples](../../pkg/test/README.md).

## Prerequisites

- Run from the repository root with the MISE-pinned Go toolchain and available
  Go dependencies. Native checks support Linux, macOS and Windows.
- Container checks require non-root Linux amd64/arm64 and a local Docker daemon
  or rootless Podman on the same architecture; emulated execution is not supported.
- No provider credentials, running Bifröst service or SSH target are needed.

## Run

```text
mise run test:policy
mise run test:policy:oci
```

These use `var/policy-ci` and `var/policy-oci`, respectively. The output directory
must **not exist**. For another run, choose a fresh path instead of deleting
previous results:

```text
mise x -- go run ./test/policyci --output var/policy-ci-another-run
mise x -- go run ./test/policyci --oci --runtime docker --output var/policy-oci-another-run
```

For rootless Podman, use `--runtime podman` with `--oci` and a fresh output path.

## Checks

The harness builds the native CLI and checks passing tests, expected assertion
failures, empty selections, invalid input, report replacement and report-write
errors. It validates process exits and text/JSON/JUnit agreement independently
of the runner's report model. Expected CLI exits 1 and 2 are successful harness
checks only when the corresponding error/failure details also match.

Container mode runs the same binary in the regular Generic Linux image and
compares results. It enforces non-root execution, no network or capabilities,
no-new-privileges, read-only inputs/root filesystem and bounded resources.
Cleanup removes only this run's owned containers and image tag. Linux container
results do not establish native Windows/macOS behavior or release attestations.

## Outputs

- `OUTPUT/reports/`: manifest, build/process logs and JSON/JUnit results,
  including expected negative cases. Retain this directory as a CI artifact
  even when a check fails; link results from the PR rather than maintaining a
  versioned execution log.
- `OUTPUT/private/`: executable, generated inputs and, in container mode, image
  archives. Do not upload this directory.

The harness exits nonzero if a build, validation, runtime or cleanup check fails.
Reports can contain fixture values and source paths; use synthetic data.
