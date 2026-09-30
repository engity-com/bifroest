# Nano Server local-environment integration

This opt-in test runs the pinned `mcr.microsoft.com/windows/nanoserver:ltsc2022` image used by Bifroest. It checks that the Windows Bifroest executable starts in Nano Server, required DLL exports resolve at runtime, and ConPTY produces output. A new feature-gated Nano Server test exercises creation, managed-group enrollment, display-name update and deletion of a disposable local SAM account. A separate pinned Server Core LTSC2022 image verifies the temporary LocalSystem service, passwordless S4U, Exec and PTY with a local SAM account.

These are opt-in capability tests, not proof that Nano Server SAM or S4U works on all runtimes, or a test of the released image's default entrypoint as a LocalSystem service. The default container startup does not run Bifroest as LocalSystem; runtime S4U with `environment.type: local` requires a proper service-based startup configuration. The SAM calls try `netapi32.dll` first, then `samcli.dll` from System32 if an export is unavailable; this fallback does not imply that undocumented APIs are officially supported.

Run it on a Windows host (or Windows VM) with a working **Windows-container** Docker daemon, Hyper-V isolation support, and Go 1.27. From the repository root in Nushell:

The `cmd/build` binary stage requires `GITHUB_TOKEN`; the GitHub Actions workflow supplies a read-only token. Set it explicitly when running these tasks outside CI.

```nu
$env.BIFROEST_TEST_NANOSERVER = "1"
mise run build:go:binary -- --os=windows --arch=amd64 --edition=generic
mise run test:e2e:nanoserver
```

Without `BIFROEST_TEST_NANOSERVER=1` the test is skipped. With it enabled, a missing or Linux Docker daemon is a **failure**, not a skip. Hyper-V isolation is the default; `BIFROEST_TEST_NANOSERVER_ISOLATION=process` is an explicit opt-in to weaker process isolation on a compatible Windows host. Do not run this test on a production Windows host.

The test uses the Windows/amd64 binary built by `cmd/build`, builds temporary test helpers and ephemeral images from both pinned bases, uses no writable host mounts and publishes no ports, then removes its image tags. Base images may remain in the Docker cache. Nano Server's built-in `ContainerUser` is not a local SAM account. The guarded Nano SAM lifecycle test runs as `ContainerAdministrator` and creates a random account and group **only inside a disposable Nano Server container**; it checks their SIDs, direct membership and display name, then deletes the account. The guarded Server Core helper likewise creates a random account only inside its disposable container and starts a temporary LocalSystem service to test S4U, user-profile loading, Exec and PTY. No host account or service is changed.

The GitHub Actions `Nano Server Integration` workflow runs this task on a disposable `windows-2022` runner with process isolation, if its Windows Docker daemon is available. For Hyper-V isolation use a dedicated Windows Docker runner instead. A successful cross-build or a native Windows host test does **not** replace these container tests; the Nano SAM lifecycle and Server Core S4U tests must pass separately before claiming those capabilities for the tested runtime.
