---
description: Export SSH public keys, certificate authorities and host trust entries.
---

# `bifroest key export`

Export public SSH trust material. The selected subcommand determines which identity supplies the public key and how the result is formatted.

## Commands

| Command | Purpose |
| --- | --- |
| [`public`](public.md) | Export the public half of a local private identity. |
| [`ca`](ca.md) | Export the effective certificate authority of a configured SSH flow. |
| [`host`](host.md) | Export host keys as OpenSSH `known_hosts` entries. |

Output files are selected with the subcommand's `--output` option. Public exports can be transferred through a trusted provisioning channel; private identities stay on their source machine.

## Examples

* [Configure encrypted evidence](../../../../guides/evidence.md) with a dedicated recipient public key.
* [Configure certificate authentication](../../../environment/ssh.md#openssh-certificate-authentication) using exported CA and host keys.
