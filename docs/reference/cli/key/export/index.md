---
description: Export SSH public keys, certificate authorities and host trust entries.
---

# `bifroest key export`

Export public SSH trust material. The selected subcommand determines which identity supplies the public key and how the result is formatted.

## Commands

| Command | Purpose |
| --- | --- |
| [`public`](public.md) | Export a local identity's public half or a configured server SSH identity. |
| [`ca`](ca.md) | Export the effective certificate authority of a configured SSH flow. |
| [`host`](host.md) | Export host keys as OpenSSH `known_hosts` entries. |

With the local or integrated CLI, `--output` selects a file on the CLI machine. Direct SSH writes stdout only. Remote export uses existing configured keys and needs no optional management permission. Private identities stay on their source machine.

## Examples

* [Configure encrypted evidence](../../../../guides/evidence.md) with a dedicated recipient public key.
* [Configure certificate authentication](../../../environment/ssh.md#openssh-certificate-authentication) using exported CA and host keys.
* [Export server public keys remotely](../../../../guides/keys.md) using a configured management connection.
