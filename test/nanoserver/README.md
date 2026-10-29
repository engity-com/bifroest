# Nano Server local-environment integration

This opt-in test runs the pinned `mcr.microsoft.com/windows/nanoserver:ltsc2022` image used by Bifroest. It checks that the Windows Bifroest executable starts in Nano Server, required DLL exports resolve at runtime, and ConPTY produces output. A new feature-gated Nano Server test exercises creation, managed-group enrollment, display-name update and deletion of a disposable local SAM account. A separate pinned Server Core LTSC2022 image verifies the temporary LocalSystem service, passwordless S4U, Exec and PTY with a local SAM account, followed by the actual embedded browser against the native Windows Bifroest service.

These are opt-in capability tests, not proof that Nano Server SAM or S4U works on all runtimes, or a test of the released image's default entrypoint as a LocalSystem service. The default container startup does not run Bifroest as LocalSystem; runtime S4U with `environment.type: local` requires a proper service-based startup configuration. The SAM calls try `netapi32.dll` first, then `samcli.dll` from System32 if an export is unavailable; this fallback does not imply that undocumented APIs are officially supported.

Run it on a Windows host (or Windows VM) with a working **Windows-container** Docker daemon, Hyper-V isolation support, and Go 1.27. From the repository root in Nushell:

The `cmd/build` binary stage requires `GITHUB_TOKEN`; the GitHub Actions workflow supplies a read-only token. Set it explicitly when running these tasks outside CI.

```nu
$env.BIFROEST_TEST_NANOSERVER = "1"
mise run install:web
mise run install:web:browser
mise run build:web
mise run build:go:binary -- --os=windows --arch=amd64 --edition=generic
mise run test:e2e:nanoserver
```

Without `BIFROEST_TEST_NANOSERVER=1` the test is skipped. With it enabled, a missing or Linux Docker daemon is a **failure**, not a skip. Hyper-V isolation is the default; `BIFROEST_TEST_NANOSERVER_ISOLATION=process` is an explicit opt-in to weaker process isolation on a compatible Windows host. Do not run this test on a production Windows host.

The test uses the Windows/amd64 binary built by `cmd/build`, builds temporary test helpers and ephemeral images from both pinned bases, uses no writable host mounts and publishes no ports, then removes its image tags. Base images may remain in the Docker cache. Nano Server's built-in `ContainerUser` is not a local SAM account. The guarded Nano SAM lifecycle test runs as `ContainerAdministrator` and creates a random account and group **only inside a disposable Nano Server container**; it checks their SIDs, direct membership and display name, then deletes the account. The guarded Server Core helper likewise creates a random account only inside its disposable container and starts a temporary LocalSystem service to test S4U, user-profile loading, Exec and PTY. No host account or service is changed.

The GitHub Actions `Nano Server Integration` workflow runs this task on a disposable `windows-2022` runner with process isolation, if its Windows Docker daemon is available. For Hyper-V isolation use a dedicated Windows Docker runner instead. A successful cross-build or a native Windows host test does **not** replace these container tests; the Nano SAM lifecycle and Server Core S4U tests must pass separately before claiming those capabilities for the tested runtime.

## Actual Server Core / browser path

The required `servercore-native-browser` subtest starts the **real built Windows
Bifroest executable** through its existing Windows service runner as LocalSystem.
The registered command explicitly includes `--windowsService` and its registered
`--serviceName`; parent-process detection alone is not reliable inside Server Core
containers. The ordinary foreground default remains unchanged. A small marked
LocalSystem preparation service creates the private fixture state with the correct
native owner before the real gateway starts. It is only a file/bootstrap step,
not a substitute gateway or an authorization server. Private-key owner/DACL checks
remain unchanged; ContainerAdministrator-owned keys are not accepted by exception.
Bootstrap requires ContainerAdministrator, an explicit container-only environment
gate and the owned Server Core image marker. Only a new random container-local
SAM account is used; no host service, account, logon right or TCB privilege is
changed. Server state and keys are separate from the target-readable executable
directory. The test client private key stays on the host, outside even the Docker
build context; only its public key enters the image.

Pinned host Chromium uses the embedded key-WASM/xterm UI over direct TLS/HTTP2 to
the container's private IPv4 address (exact Host/SNI/Origin `app.example.org:8443`).
No host ports are published and no SSH tunnel, iframe, management CLI web action
or substitute test server is involved. A separate native Go SSH client keeps a
real execution alive while the browser closes a live sibling tab, reloads and
logs out. A native helper reports its actual process token SID, profile, reserved
session/connection IDs and console dimensions. A changed size must reach the
actual ConPTY before the helper confirms it. Profile-marker reads through an
independent container inspection confirm that the workload survives each action.

Five deliberate browser shells and three SSH executions (including an actual
SSH PTY reference using the real executable, not the test-binary relay) share one
stored native session, have distinct connection IDs, and retain the same target
SID. Browser exits 7 and 0 must be explicitly validated; live transport retirement
must not infer a successful exit. After a clean Windows-service stop, the existing
Go audit/recording verifiers check every signed artifact against the independent
fixture producer pin and correlate all eight task/connection/operation records.
The copied session association must still identify the original local SID and
must not be disposed. This does not enable Windows SAM password RememberMe or
claim that service installation inside a container is the released image's default
entrypoint. Native runtime results remain required; a cross-build alone is not
acceptance.

## Native password-policy observations (not RememberMe activation)

The required `servercore-native-password-policy` test uses a separate owned
Server Core container and the marked temporary LocalSystem service. It creates
only random container-local SAM accounts/groups. Each restriction must actually
reject regular `LogonUserW` network authentication with the fixture's in-memory
password before S4U observations are accepted as useful evidence. The matrix
includes disabled/expired accounts, denied logon hours, workstation restriction,
required password change, direct/group-based denied network-logon rights and
blank-password network rejection with and without the password-required flag,
actual elapsed password-age expiry and actual account lockout.
The latter creates new accounts without an initial password rather than resetting
a strong password to empty (which would require weakening password complexity).
Their initial password-expired marker is explicitly cleared and read back only
on those owned fixture accounts; otherwise a forced-password-change rejection
could be mistaken for a blank-password policy rejection.
The same account must first authenticate with the blank restriction disabled and
then fail with it enabled. These exact DWORD changes affect only the separate
owned container's local registry view; the original value is restored and verified.
No host registry or host policy is accessed and password complexity is unchanged.
Only those newly created SID-bound records/rights are changed and cleaned up;
Host accounts, host security settings and privileges are not modified.

Both existing S4U flags0 and `MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS` (2) are
observed, including the actual resulting token SID. A denied reference followed
by S4U success is logged as a policy gap, **not** converted into eligibility or a
feature pass. Password/interactive RememberMe stays unavailable. This matrix is
a prerequisite to a complete secretless policy adapter, not its implementation;
identity replacement, races and cleanup/API failures still need additional strict
coverage before activation. New expiry/lockout references must pass natively too.

The expiry/lockout fixtures first bind `NetUserModalsGet(2)` to their owned local
SAM domain SID and machine name. Only that separate container's maximum password
age or lockout threshold/window is tightened; scalar original policies are restored
and read back. Minimum password age, minimum length, complexity and history are
never lowered. The expiry fixture refuses an incompatible minimum age rather
than weakening it. Lockout must follow an actual wrong-password logon, not an
injected lockout flag. No host SAM policy is accessed.

Accepted S4U tokens additionally expose only their own native logon-data size and
nonsecret password timestamps through `LsaGetLogonSessionData`, with strict native
structure-size/LUID/SID checks. Microsoft explicitly permits `PasswordLastSet` to
remain uninitialized. A zero timestamp is recorded as missing evidence, never as
a credential generation or permission; no profile, environment, secret or rights
snapshot is read or replayed by this observation.

The candidate additionally reads fresh `NetUserGetInfo(3)` and
`NetUserModalsGet(0)` data, binds the returned RID to the selected SID and checks
disabled/locked/expired accounts, forced password changes and password-age limits.
In particular, the observed S4U password-must-change bypass must be rejected by
this separate read. This remains a **preliminary restriction check**, not an
eligibility interface: no missing blank-password, native logon-right, current
identity/template or cleanup/cancellation proof is inferred from an empty reason.

An additional required **observation**, not an eligibility gate, queries only
SAM domain creation/update metadata through the local client library with
connect/lookup and read-other-parameters access. It records whether ordinary
password/S4U logons leave that marker unchanged and whether a strong password
reset on its own account changes it. Missing exports/unsupported metadata are
reported explicitly as unavailable, not converted into permission. No user
password/hash/private SAM information is queried. The documented SAMR RPC
structure does not establish a stable local DLL ABI or complete update coverage;
both need native evidence before any production use. A domain-wide marker would
also have wider revocation effects and needs a separate design/security decision.

A separate required research observation queries **only local SAM class 29**
(`UserLogonUIInformation`), described in System Informer's `ntsam.h` as the two
booleans `PasswordIsBlank` and `AccountIsDisabled`. It compares owned strong,
strong-with-not-required-flag, blank, blank-with-required-flag and disabled
accounts. A same-account blank-to-strong reset retains `PASSWORD_NOT_REQUIRED`,
requires a fresh query before any reference logon, one real strong-password logon
and two further fresh query handles afterward, without a login-warmed cache as
the only source of evidence.
Only its own fixture password is changed; no machine password policy is relaxed.
The query requests read-only
user/domain access, never user-all/internal/password/hash/private information.
Unknown exports/classes, non-BOOLEAN layouts, identity drift, cancellation and
cleanup errors yield no observation, not eligibility. This reverse-engineered
header is not a Microsoft ABI/support or security-contract guarantee; neither
its availability nor correct behavior is assumed before native execution, and
even passing fixture observations do not activate password resumption.
