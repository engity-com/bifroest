# Native Linux PAM / browser integration

Run `mise run install:web:browser`, then
`BIFROEST_E2E_RUNTIME=podman mise run test:e2e:pam` from Bash on a native Linux
container host. CI uses its own Docker runtime instead. The task builds browser
assets before Go embedding and requires the pinned MISE Go/Node installations.

The harness derives its base from `cmd/build/build-matrix.go`, mounts source,
modules, MISE toolchains and the installed Chromium cache read-only, and builds
with that image's C compiler/PAM headers. The only writable host mount is an owned
Go cache; native account/PAM changes stay in the disposable container filesystem.
The runtime container has no network except loopback, runtime socket, privileged
mode or host account access. A unique container/image is cleaned up by exact name.
The image marker and explicit environment gate must both be present before the
native fixture creates its disposable `alice` account or PAM service. It never
changes host PAM, creates host users or grants host privileges.

Actual `pam_unix` authentication/account checks and `pam_access` enforce policy.
The test-only C module has only an account entry point: it checks `PAM_RHOST` and
loads a fresh synthetic environment value, never a password. An auth-stack counter
proves that enrollment/resumption, including after service restart, do not call
`pam_authenticate`. Tests cover explicit server opt-out, real TLS/HTTP2 proof
requests, fresh environment, policy changes after challenge issuance, native
password lock, retained binding state and actual Chromium password/interactive
RememberMe across profile restart. They use the shared service execution fixture;
they do not claim native local shell/ConPTY or container-workload coverage.

`var/e2e/pam-browser.json` is required to contain successful, non-skipped results
for every native test. Ordinary unit-test runs skip these container-only tests.
Set `BIFROEST_TEST_PAM_RACE=1` and, optionally, `BIFROEST_TEST_PAM_COUNT=2` for
explicit race/repetition runs; neither setting adds production retries.
