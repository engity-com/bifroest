---
description: Generate and exchange SSH trust material with Bifröst.
---

# `bifroest key` {: #ssh-trust-bootstrap }

Key commands generate and exchange SSH trust material for an [SSH environment](../../environment/ssh.md) and [Bifröst delegation authorization](../../authorization/bifroest.md). Only `key import host --address` contacts a remote host.

Exchange exported public material and SHA256 fingerprints over an independently trusted channel.

## Commands

| Command | Purpose |
| --- | --- |
| [`generate`](generate.md) | Create a new Ed25519 key pair. |

### `export` {: #export }

| Command | Purpose |
| --- | --- |
| [`public`](export/public.md) | Export a public key from a private identity. |
| [`ca`](export/ca.md) | Export the effective SSH certificate authority of a flow. |
| [`host`](export/host.md) | Create `known_hosts` entries without network access. |

### `import` {: #import }

| Command | Purpose |
| --- | --- |
| [`ca`](import/ca.md) | Import trusted SSH certificate authorities. |
| [`host`](import/host.md) | Import trusted SSH host keys. |

Some key bootstrap operations create missing identities, unlike the read-only audit and Recording commands.

## Examples

* [Configure encrypted audit and Recording evidence](../../../guides/evidence.md) with a dedicated recipient pair.
* [Configure OpenSSH certificate authentication](../../environment/ssh.md#openssh-certificate-authentication) using CA and host-key exchange.
