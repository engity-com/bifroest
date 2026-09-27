# Nano Server local-environment integration

This opt-in test runs the pinned `mcr.microsoft.com/windows/nanoserver:ltsc2022` image used by Bifroest. It checks that the Windows Bifroest executable starts in the container, required DLL exports resolve at runtime, ConPTY produces output, and a temporary LocalSystem service can run the S4U/Exec/PTY tests against an existing account inside the container.

This is a capability test, not a test of the released image's default entrypoint as a LocalSystem service. The default container startup does not run Bifroest as LocalSystem; running `environment.type: local` in that image requires a separate service-based startup configuration.

Run it on a Windows host (or Windows VM) with a working **Windows-container** Docker daemon, Hyper-V isolation support, and Go 1.27. From the repository root in Nushell:

```nu
$env.BIFROEST_TEST_NANOSERVER = "1"
mise run test:e2e:nanoserver
```

Without `BIFROEST_TEST_NANOSERVER=1` the test is skipped. With it enabled, a missing or Linux Docker daemon is a **failure**, not a skip. Hyper-V isolation is the default; `BIFROEST_TEST_NANOSERVER_ISOLATION=process` is an explicit opt-in to weaker process isolation on a compatible Windows host. Do not run this test on a production Windows host.

The test builds temporary binaries, builds an ephemeral image from the pinned base, uses no writable host mounts and publishes no ports, then removes its image tag. The base image may remain in the Docker cache. Nano Server's built-in `ContainerUser` is not a local SAM account. An explicitly guarded test helper creates a random local account and profile **only inside the disposable container**, then starts a temporary LocalSystem service to test S4U/Exec/PTY. The provider itself does not create or remove accounts; no host account or service is changed.

The GitHub Actions `Nano Server Integration` workflow runs this task on a disposable `windows-2022` runner with process isolation, if its Windows Docker daemon is available. For Hyper-V isolation use a dedicated Windows Docker runner instead. A successful cross-build or a native Windows host test does **not** replace this container test.
