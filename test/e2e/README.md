# Integration test builds

Run the authorization suite with the pinned MISE toolchain:

```sh
mise run test:e2e:authorization
```

Its `build:e2e:authorization` prerequisite compiles both fixture build modes
before the existing five-minute Go test deadline starts. A cold compiler cache
must not consume the authorization/OIDC execution budget. The deadline, complete
test selection, assertions and per-operation timeouts are unchanged.

The warm outputs under `var/e2e/authorization-build-cache` are **not** passed to
tests. Every fixture still builds its own binaries from the current checkout,
with its own version, keys, state and processes. Only Go's normal compilation
cache is warmed; no permission, credential, environment or workload is reused.
Calling `go test` directly bypasses this explicit build prerequisite.

The authorization suite does not require a container runtime. For suites that
do, select an owned working runtime explicitly, for example
`BIFROEST_E2E_RUNTIME=podman`; do not use an unrelated cluster or daemon.
