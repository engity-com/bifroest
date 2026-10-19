---
description: Generate and exchange SSH trust material with Bifröst.
---

# `bifroest key` {: #ssh-trust-bootstrap }

Key commands generate and exchange SSH trust material for an [SSH environment](../../environment/ssh.md) and [Bifröst delegation authorization](../../authorization/bifroest.md). Public exports support the [management client and direct SSH](../management.md); `generate` and `import` are local-only. `key import host --address` can additionally retrieve a host key from the CLI machine.

Exchange exported public material and SHA256 fingerprints over an independently trusted channel.

## Commands

| Command | Purpose |
| --- | --- |
| [`generate`](generate.md) | Create a new Ed25519 key pair. |
| [`export`](export/index.md) | Export public keys, certificate authorities and host trust entries. |
| [`import`](import/index.md) | Validate and merge public certificate authorities or host trust entries. |

Some local bootstrap operations create missing identities. Server-side exports only expose existing public material. Configure server trust files through the host's normal configuration management.

## Examples

* [Configure encrypted audit and Recording evidence](../../../guides/evidence.md) with a dedicated recipient pair.
* [Configure OpenSSH certificate authentication](../../environment/ssh.md#openssh-certificate-authentication) using CA and host-key exchange.
* [Export server public keys remotely](../../../guides/keys.md) using a separate management flow.
