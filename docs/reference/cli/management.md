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

`@target` must precede all other arguments. The leading `@` is reserved for remote selection; Kingpin's argument-file syntax `@file` is not available as the first argument. Direct SSH commands execute inside the management flow and do not start a shell.

| Subject | Commands | Notes |
| --- | --- | --- |
| `session` | `ls`, `show <id>` | `ls` defaults to authorized, non-expired sessions; use `--state=all`, `--flow` and `--user` for more. |
| `flow` | `ls`, `show <name>` | Settings are redacted unless that management flow explicitly enables `includingCredentials`. |
| `auditlog` | `ls`, `show <name>`, `events <name>` | `events` is signature-verified; private fields require `--with-sensitive`. |
| `recording` | `ls <auditlog>`, `show <auditlog> <id>`, `play` | An encrypted Recording reports outer verification until the matching local private key is supplied for full verification and playback. |

Lists display tables and detail commands display key/value lists by default. Use `--format=json` or `--format=yaml` for structured output. This is independent of the existing `--output` flag, which chooses an export **file**. Local `audit verify/export/merge` and `recording verify/export` commands remain available. Remote Recording `verify`, `export`, and `play` use an SSH transfer of the signed original, verify it on the CLI machine, and never transmit a decryption private key to the server. `recording play` and export require `--with-sensitive`.

Local file inputs, such as `audit verify --source ./journal` and `recording verify ./file.becast`, are not remote paths. Use a configured auditlog and Recording ID for remote selection. Output files and decryption-key files always refer to the CLI machine.

## SSH client and trust

The `bifroest @target` client is integrated into the binary. It uses SSH configuration for host aliases, `HostName`, `User`, `Port`, `IdentityFile`, `IdentityAgent`, and `UserKnownHostsFile`. The host must have a trusted entry in `known_hosts`; Bifröst does not automatically accept an unknown host key. Unsupported SSH proxy directives such as `ProxyJump` and `ProxyCommand` fail explicitly. Other complex OpenSSH configurations might need to be simplified for this integrated client.

For SSH authentication, Unix-like systems use `SSH_AUTH_SOCK`. On Windows, the client first tries the Windows OpenSSH agent named pipe, then Pageant's native agent interface. The agent is used **only for SSH login**, not to decrypt audit or Recording content. In a container, mount the agent socket and/or identity files, SSH configuration, and `known_hosts` when needed; no `ssh` executable is required inside the container.

Custom per-host SSH configuration is supported (the `IgnoreUnknown` directive allows the same file to be read by OpenSSH):

```sshconfig
IgnoreUnknown X-*

Host bifroest-admin
    HostName bifroest.example.org
    User management
    X-RecordingPrivateKey ~/.ssh/bifroest-recording-decryption
    X-ExpectedProducerId 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`X-RecordingPrivateKey` names a **local** private-key file; `X-ExpectedProducerId` pins an independently trusted audit/Recording signing producer ID. Both can be overridden with command-specific flags. Keep signing and encryption keys distinct and retain producer IDs independently of copied evidence. A server-supplied ID is not a trust anchor.

Without a matching private key, encrypted audit events and Recordings expose only their verified public/outer metadata. Direct SSH sessions cannot use a private key kept only on a separate CLI machine.
