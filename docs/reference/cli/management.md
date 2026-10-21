---
description: Connect Bifröst's integrated CLI or a standard SSH client to an authorized management flow.
---

# Remote access

<span id="management-commands"></span>

Remote access uses the same command names as the local CLI. For a complete server and client configuration, follow [Manage a Bifröst host remotely](../../guides/management.md). The [management environment](../environment/management.md) reference describes the server-side properties.

## Select a target

The integrated client accepts `@[USER@]HOST[:PORT]` as the **first argument**:

```shell
bifroest @bifroest-admin session ls
bifroest @management@bifroest.example.org flow ls --format=json
bifroest @[::1]:2222 audit ls
```

`@target` selects remote execution for the entire command. Unsupported commands and flags fail instead of falling back to local execution. A target in a later position is rejected. Management commands do not support `@file` argument expansion.

## SSH client and trust

The client is integrated into the Bifröst binary; it needs no separate `ssh` executable. It reads SSH host aliases and the settings `HostName`, `User`, `Port`, `IdentityFile`, `IdentityAgent` and `UserKnownHostsFile`. A trusted host key must already be present in `known_hosts`; unknown keys are not automatically accepted.

`UserKnownHostsFile` selects one local file; the client default is `~/.ssh/known_hosts`. Quote paths containing spaces in the SSH configuration, for example `UserKnownHostsFile "C:/Users/Alice Example/.ssh/known_hosts"` on Windows. Use a single trust file for the integrated client rather than a list of files in this setting.

Unsupported proxy directives such as `ProxyJump` and `ProxyCommand` fail explicitly. Other complex OpenSSH configurations may need to be simplified for this client.

### Isolated client configuration

The integrated parser supports a subset of OpenSSH configuration syntax. In particular, `Match final` is not interpreted; configurations containing it fail explicitly. To use the integrated client on a host whose normal SSH configuration needs unsupported rules, select a separate file with `--sshConfig PATH` (short option `-F`):

```sshconfig title="Administrator workstation: bifroest-ssh.conf"
IgnoreUnknown X-*

Host bifroest-admin
    HostName bifroest.example.org
    User management
    IdentityFile ~/.ssh/bifroest-management
    UserKnownHostsFile ~/.ssh/known_hosts
```

```shell title="Administrator workstation"
bifroest @bifroest-admin --sshConfig ./bifroest-ssh.conf session ls
bifroest @bifroest-admin -F ./bifroest-ssh.conf audit ls
```

The selected file replaces the normal user and system SSH configuration. Its explicit `Include` directives are still processed. Login identities, host trust and the `X-*` artifact settings below are all taken from this same source. A missing or invalid selected file causes an error; it never falls back to another configuration, ignores an unsupported Match rule, or accepts an unknown host key. These options belong to the integrated client and are not available through direct management SSH.

### Authentication agents

On Unix-like systems, agent authentication uses `SSH_AUTH_SOCK`. On Windows, the client tries the OpenSSH agent named pipe for at most five seconds, then Pageant's native interface. Canceling the command also closes an OpenSSH-agent connection waiting for a response.

When both Windows agents are running, set `X-SSHAgent pageant` in the matching `Host` block to select Pageant. It cannot be combined with `IdentityAgent`. Modern Pageant versions can also expose an OpenSSH-compatible named pipe through `IdentityAgent`.

The agent authenticates the SSH connection. Audit and Recording decryption use separate local private-key files. In a container, provide the agent socket or login identity, SSH configuration and trusted host keys as needed.

### Authentication prompts

Passphrases for encrypted SSH identities, passwords and keyboard-interactive answers are read from the invoking terminal. Prompts and visible answers are written to stderr; secret answers are hidden. Each answer is limited to 64 KiB; exceeding that limit causes an explicit error rather than truncation. Press `Ctrl+C` to cancel a prompt without pressing Enter. The original terminal settings are restored when the prompt finishes or is canceled.

For non-interactive commands, provide an SSH agent or a usable identity file. The client does not read passwords from a pipe or from command output.

### Artifact settings

The integrated client recognizes these additional SSH settings:

| Setting | Meaning |
| --- | --- |
| `X-ExpectedProducerId` | Independently trusted signing producer ID for downloaded evidence. |
| `X-AuditPrivateKey` | Local private-key file for encrypted audit event fields. |
| `X-RecordingPrivateKey` | Local private-key file for encrypted Recordings. |
| `X-SSHAgent` | Explicit `pageant` selection for SSH login. |

Use `IgnoreUnknown X-*` when sharing this configuration with OpenSSH. Artifact commands can override producer trust with `--expectedProducerId` and decryption keys with `--decryptionIdentityFile`. A server-supplied or artifact-embedded producer ID is not an independent trust anchor; see [Trust and verification](verification.md).

## Direct SSH

A standard SSH client can execute a command in the authorized management flow:

```shell
ssh management@bifroest.example.org 'session ls'
ssh management@bifroest.example.org 'recording show default RECORDING_UUID'
```

The flow does not start a shell or provide PTY, SFTP or forwarding access. Commands use the service's loaded configuration. Each command page states whether direct SSH is supported and which flags differ from the integrated client.

Direct SSH cannot use decryption keys stored on a separate workstation. It can verify signed outer metadata and clear content on the server. Use the integrated client for local decryption of downloaded evidence.

## Permissions and downloads

| Operation | Requires `allowArtifactTransfer: true` |
| --- | --- |
| Session, flow, auditlog and Recording metadata | No |
| [`session disconnect`](session/disconnect.md) and [`session dispose`](session/dispose.md) | No |
| Public `audit events` | No |
| Client-side `audit verify/export/merge` or sensitive `audit events` | Yes |
| Client-side `recording verify/export/play` | Yes |
| Direct-SSH verification without content export | No |
| Direct-SSH sensitive audit output or Recording export/play | Yes |
| Public `key export public/ca/host` | No |

These are properties of the authorized management flow, not client-granted privileges. `--with-sensitive` controls disclosure by a command; it does not grant server permissions. `includingCredentials` separately controls the management flow's `flow show` output. See [management environment properties](../environment/management.md#configuration).

Every authorized management user can disconnect or dispose of sessions in any flow, even with both environment permissions disabled. Disposal also runs configured cleanup and can remove workload resources; management access is not read-only.

Public key exports select configured server identities and write their output on the CLI machine. See [Export server public keys remotely](../../guides/keys.md) for a complete configuration. `key generate` and `key import` remain local-only; server trust files are maintained through normal configuration management.

Remote artifact commands download the selected audit journal or original Recording and verify it on the CLI machine. Private decryption keys stay there. An audit download is limited to **1 GiB** of journal files; Recording downloads are subject to the [Recording size limits](../../formats/recording.md). A live journal that changes during the download can cause an error and require a retry.

## Examples

### Configure a workstation alias

1. Configure an authorized [management flow](../../guides/management.md) and provision the server's host key through a trusted channel.
2. Add the host to the workstation's SSH configuration:

    ```sshconfig title="~/.ssh/config"
    IgnoreUnknown X-*

    Host bifroest-admin
        HostName bifroest.example.org
        User management
        IdentityFile ~/.ssh/bifroest-management
        UserKnownHostsFile ~/.ssh/known_hosts
    ```

3. Query server state:

    ```shell
    bifroest @bifroest-admin session ls
    bifroest @bifroest-admin audit ls --format=json
    ```

For producer-ID pinning and decryption-key configuration, follow [Verify encrypted evidence on a workstation](../../guides/evidence.md).
