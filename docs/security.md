---
description: Understand Bifröst SSH trust boundaries, service privileges, session storage, audit evidence and release checks.
---

# Security and trust

Bifröst accepts SSH connections, selects an [authorization and session environment](reference/flow.md), and can connect to a separate SSH target. The security of an installation depends on its access policy, service permissions, identity provider, target systems and storage. Start with a configuration for your actual workflow, not an assumed `sshd`-compatible default.

## Identity and SSH targets

* An [OIDC Device login](guides/oidc.md) requires a browser and an identity provider that supports the flow. By default it also requires a refresh token: Bifröst checks the grant while the session is active, and closes its SSH connections if access is lost. Check whether the IdP invalidates existing refresh grants on user disablement; this is not an instant global logout. Keep the client secret and session storage restricted to the service operator; Bifröst stores authorization data in its session repository.
* An [SSH gateway](guides/ssh-gateway.md) ends the incoming SSH connection and opens a separately authenticated one to the target. Configure and verify the target's host key; the gateway's incoming host key does not prove the identity of that target.
* [Connection](reference/connection/ssh.md#property-maxTimeout) and [session](reference/session/fs.md#property-maxTimeout) maximum lifetimes can be configured. For a time-bound [off-boarding requirement](usecases.md#offboard), test both new and existing access against the actual IdP and target systems.

## Service and storage permissions

Local-account sessions require privileges to run processes as the selected user: normally root on Linux and macOS, or LocalSystem for a Windows service. Protect the configuration, private keys, session directory and backups. Access to a Docker daemon or its socket grants extensive control over the host; container isolation depends on the runtime permissions and mounts you configure.

Audit logging and recording are **off by default**. When enabled, Bifröst can produce [signed audit journals](reference/auditlog/index.md) and [verifiable terminal recordings](guides/recording.md). Signatures protect integrity, not confidentiality: configure a separate encryption recipient when needed. Recordings capture shell/command output, not raw keystrokes or SFTP and forwarding payloads. Treat exports as sensitive; protect the signing key and independently retain the [producer ID](reference/cli/audit/producer-id.md) needed to verify copied evidence.

## Verification and disclosure

The repository includes automated Go tests, race tests, end-to-end scenarios and CodeQL checks. The OIDC E2E test uses a simulated IdP; it does not certify every external provider. For a **published release**, the [distribution page](setup/distribution.md#compliance) links archive checksums, a release manifest, third-party notices and per-variant SBOMs. Inspect the artifacts for the version you actually install; checksums and tests are not a claim of an independent security audit.

Report vulnerabilities through the <<asset_link("SECURITY.md", "security policy") >>. For an overview of where Bifröst fits, see [Choosing an SSH access approach](choosing-bifroest.md).
