# Nano Server local-environment integration

This opt-in test runs the pinned `mcr.microsoft.com/windows/nanoserver:ltsc2022` image used by Bifroest. It checks that the Windows Bifroest executable starts in Nano Server, required DLL exports resolve at runtime, and ConPTY produces output. A separate pinned Server Core LTSC2022 image verifies the temporary LocalSystem service, passwordless S4U, Exec and PTY with an existing local SAM account.

This is a capability test, not a test of the released image's default entrypoint as a LocalSystem service. The default container startup does not run Bifroest as LocalSystem; running `environment.type: local` in that image requires a separate service-based startup configuration.

Run it on a Windows host (or Windows VM) with a working **Windows-container** Docker daemon, Hyper-V isolation support, and Go 1.27. From the repository root in Nushell:

```nu
$env.BIFROEST_TEST_NANOSERVER = "1"
mise run test:e2e:nanoserver
```

Without `BIFROEST_TEST_NANOSERVER=1` the test is skipped. With it enabled, a missing or Linux Docker daemon is a **failure**, not a skip. Hyper-V isolation is the default; `BIFROEST_TEST_NANOSERVER_ISOLATION=process` is an explicit opt-in to weaker process isolation on a compatible Windows host. Do not run this test on a production Windows host.

The test builds temporary binaries and ephemeral images from both pinned bases, uses no writable host mounts and publishes no ports, then removes its image tags. Base images may remain in the Docker cache. Nano Server's built-in `ContainerUser` is not a local SAM account, and the pinned image lacks `netapi32.dll` for provisioning a SAM test fixture. An explicitly guarded test helper creates a random local account **only inside the disposable Server Core container**, then starts a temporary LocalSystem service to test S4U, user-profile loading, Exec and PTY. The provider itself does not create or remove accounts; no host account or service is changed.

The GitHub Actions `Nano Server Integration` workflow runs this task on a disposable `windows-2022` runner with process isolation, if its Windows Docker daemon is available. For Hyper-V isolation use a dedicated Windows Docker runner instead. A successful cross-build or a native Windows host test does **not** replace this container test.
