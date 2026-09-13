---
description: Generate and exchange SSH trust material with Bifröst.
---

# `bifroest key` {: #ssh-trust-bootstrap }

Key commands generate and exchange SSH trust material for an [SSH environment](../../environment/ssh.md) and [Bifröst delegation authorization](../../authorization/bifroest.md). Only `key import host --address` contacts a remote host.

Exchange exported public material and SHA256 fingerprints over an independently trusted channel.

## Commands

* [`bifroest key generate`](generate.md) creates a new Ed25519 key pair.
* [`bifroest key export public`](export/public.md) exports a public key from a private identity.
* [`bifroest key export ca`](export/ca.md) exports the effective SSH certificate authority of a flow.
* [`bifroest key export host`](export/host.md) creates `known_hosts` entries without network access.
* [`bifroest key import ca`](import/ca.md) imports trusted SSH certificate authorities.
* [`bifroest key import host`](import/host.md) imports trusted SSH host keys.
