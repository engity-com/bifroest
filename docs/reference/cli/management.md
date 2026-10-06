---
description: Inspect sessions, flows, audit logs, and recordings locally or through the SSH management flow.
---

# Management commands

Commands run locally unless the **first argument** is `@[USER@]HOST[:PORT]`. That target selects remote execution for the entire command, even if a particular command does not support remote access; unsupported combinations fail with an error. A bracketed IPv6 literal can be used with a port: `@[::1]:2222`.

```shell
bifroest session ls
bifroest @management@bifroest.example.org session ls --format=json
bifroest @bifroest-admin flow show administration --format=yaml
ssh management@bifroest.example.org 'auditlog ls'
```

`@target` must precede all other arguments. The leading `@` is reserved for remote selection; `@file` argument expansion is not available in management commands, and `@target` in a later position is rejected. Direct SSH commands execute inside the management flow and do not start a shell.

| Subject | Commands | Notes |
| --- | --- | --- |
| `session` | `ls`, `show <id>` | `ls` defaults to authorized, non-expired sessions; use `--state=all`, `--flow` and `--user` for more. |
| `flow` | `ls`, `show <name>` | Configuration strings are redacted unless that management flow explicitly enables `includingCredentials`; structural names and non-string settings remain visible. |
| `auditlog` | `ls`, `show <name>`, `events <name>`, `producer-id`, `verify`, `export`, `decrypt`, `merge` | `events` is signature-verified; private fields require `--with-sensitive`. The older `audit` subject remains an alias for the artifact commands. |
| `recording` | `ls <auditlog>`, `show <auditlog> <id>`, `verify`, `export`, `play` | An encrypted Recording reports outer verification until the matching local private key is supplied for full verification, export and playback. |

Lists display tables and detail commands display key/value lists by default. Use `--format=json` or `--format=yaml` for structured output, including verification results and producer IDs. Audit export/merge remain **JSON Lines** and Recording export remains **asciicast**; those stream formats cannot be changed with `--format`. This is independent of the existing `--output` flag, which chooses an export **file**. Local `audit verify/export/merge` and `recording verify/export` commands remain available. Remote audit verification/export copies a signed journal checkpoint and verifies it on the CLI machine. Remote Recording `verify`, `export`, and `play` copy the signed original and verify it there. These remote downloads require `allowArtifactTransfer: true` on the authorized management flow, including for `verify` without `--with-sensitive`. Neither operation transmits a decryption private key to the server. `recording play` and export require `--with-sensitive`.

Local file inputs, such as `audit verify --source ./journal` and `recording verify ./file.becast`, are not remote paths. Use a configured auditlog and Recording ID for remote selection. Output files and decryption-key files always refer to the CLI machine.

## SSH client and trust

The `bifroest @target` client is integrated into the binary. It uses SSH configuration for host aliases, `HostName`, `User`, `Port`, `IdentityFile`, `IdentityAgent`, and `UserKnownHostsFile`. The host must have a trusted entry in `known_hosts`; Bifröst does not automatically accept an unknown host key. Unsupported SSH proxy directives such as `ProxyJump` and `ProxyCommand` fail explicitly. Other complex OpenSSH configurations might need to be simplified for this integrated client.

For SSH authentication, Unix-like systems use `SSH_AUTH_SOCK`. On Windows, the client first tries the Windows OpenSSH agent named pipe (for at most five seconds), then Pageant's native agent interface. OpenSSH-agent connection attempts can be canceled with the command. When both agents are running, set `X-SSHAgent pageant` in the matching SSH `Host` block to select Pageant explicitly; this cannot be combined with `IdentityAgent`. Modern Pageant versions can also provide an OpenSSH-compatible named pipe via `IdentityAgent`. The agent is used **only for SSH login**, not to decrypt audit or Recording content. In a container, mount the agent socket and/or identity files, SSH configuration, and `known_hosts` when needed; no `ssh` executable is required inside the container.

Custom per-host SSH configuration is supported (the `IgnoreUnknown` directive allows the same file to be read by OpenSSH):

```sshconfig
IgnoreUnknown X-*

Host bifroest-admin
    HostName bifroest.example.org
    User management
    X-RecordingPrivateKey ~/.ssh/bifroest-recording-decryption
    X-AuditPrivateKey ~/.ssh/bifroest-audit-decryption
    X-ExpectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`X-RecordingPrivateKey` names a **local** private-key file. For encrypted audits, use `X-AuditPrivateKey` in the same `Host` block or supply `--decryptionIdentityFile` to the command. `X-ExpectedProducerId` pins an independently trusted audit/Recording signing producer ID; artifact commands and `auditlog events --with-sensitive` also accept `--expectedProducerId`. Keep signing and encryption keys distinct and retain producer IDs independently of copied evidence. A server-supplied ID is not a trust anchor.

Without a matching private key, encrypted audit events and Recordings expose only their verified public/outer metadata. Direct SSH sessions cannot use a private key kept only on a separate CLI machine.

With `allowArtifactTransfer: false`, `auditlog` and `recording` metadata and public event queries work remotely. Direct SSH can verify artifacts on the server without downloading them; client-side `@host audit[log] verify` and `@host recording verify` require the artifact-transfer permission. Unencrypted original files can already contain sensitive information, so only grant this permission to flows whose administrators are allowed to read that evidence.

```shell
bifroest @bifroest-admin auditlog verify default
bifroest @bifroest-admin auditlog export --with-sensitive default
bifroest @bifroest-admin recording play --with-sensitive default RECORDING_UUID
ssh management@bifroest.example.org 'recording verify default RECORDING_UUID'
```

Direct SSH can export/play unencrypted Recordings with `--with-sensitive`. For encrypted content, use the Bifröst client with a local decryption key. Encrypted audit journals work similarly: direct SSH remains keyless; the CLI downloads a signed checkpoint and decrypts it locally. A remote audit checkpoint is currently limited to **1 GiB** of signed journal files; recordings use the existing native-format size limit. The snapshot is verified both before transport and again on the client. A live journal that changes while it is copied may require a retry.
