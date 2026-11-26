---
description: Understand Bifröst access boundaries, service privileges, session storage, audit evidence and release checks.
---

# Security and trust

Bifröst accepts SSH and optional HTTPS browser connections, selects an [authorization and session environment](reference/flow.md), and can connect to a separate SSH target. The security of an installation depends on its access policy, service permissions, identity provider, target systems and storage. Start with a configuration for your actual workflow, not an assumed `sshd`-compatible default.

## Identity and SSH targets

* **OIDC:** [Authorization Code and Device Authorization](reference/authorization/oidc/index.md) use an external IdP. Protect client secrets and session storage; MFA and passkeys remain with the IdP.
* **Browser-assisted SSH:** Select the two-character code from your own SSH client. Approving someone else's login link can give them access; code selection is not MFA, and IdP sign-in alone does not approve SSH.
* **OIDC access loss:** Default [refresh checks](reference/authorization/oidc/authorization-code.md#refresh-token) require a refresh token. Test the IdP's revocation behavior: disabling a user is not guaranteed to invalidate existing grants immediately.
* An [SSH gateway](guides/ssh-gateway.md) ends the incoming SSH connection and opens a separately authenticated one to the target. Configure and verify the target's host key; the gateway's incoming host key does not prove the identity of that target.
* [Connection](reference/connection/ssh.md#property-maxTimeout) and [session](reference/session/fs.md#property-maxTimeout) maximum lifetimes can be configured. For a time-bound [off-boarding requirement](usecases.md#offboard), test both new and existing access against the actual IdP and target systems.

## Service and storage permissions

Protect the [HTTPS endpoint](reference/connection/http/index.md) and any custom JavaScript. Browser verification runs locally, but its application code is supplied by the server.

Local-account sessions require privileges to run processes as the selected user: normally root on Linux and macOS, or LocalSystem for a Windows service. Protect the configuration, private keys, session directory and backups. Access to a Docker daemon or its socket grants extensive control over the host; container isolation depends on the runtime permissions and mounts you configure.

Management requires an explicitly authorized flow and [operation rights](reference/environment/management.md#property-access). Those rights apply across target flows on the connected instance; flow names are not tenant boundaries. Repository locks are not cross-host fencing. Review the [operations and availability limits](setup/operations.md) before sharing backend resources, restoring session backups or planning a standby.

Audit logging and recording are **off by default**. When enabled, Bifröst can produce [signed audit journals](reference/auditlog/index.md) and [verifiable terminal recordings](guides/recording.md). Signatures protect integrity, not confidentiality: configure a separate encryption recipient when needed. Recordings capture shell/command output, not raw keystrokes or SFTP and forwarding payloads. Treat exports as sensitive; protect the signing key and independently retain the [producer ID](reference/cli/audit/producer-id.md) needed to verify copied evidence.

## Verification and disclosure

The repository includes automated Go tests, race tests, end-to-end scenarios and CodeQL checks. The OIDC E2E test uses a simulated IdP; it does not certify every external provider. For a **published release**, the [distribution page](setup/distribution.md#compliance) links checksums, a release manifest and per-variant SBOMs, and explains where to find the included license texts and third-party notices. Inspect the artifacts for the version you actually install; checksums and tests are not a claim of an independent security audit.

Report vulnerabilities through the <<asset_link("SECURITY.md", "security policy") >>. For an overview of where Bifröst fits, see [Choosing an SSH access approach](choosing-bifroest.md).
