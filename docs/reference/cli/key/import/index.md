---
description: Validate and import public SSH trust material into local trust files.
---

# `bifroest key import`

Validate public SSH trust material and merge it into the selected trust file. An expected fingerprint can verify that the material matches a key obtained through an independent trusted channel.

## Commands

| Command | Purpose |
| --- | --- |
| [`ca`](ca.md) | Import SSH certificate-authority public keys. |
| [`host`](host.md) | Import OpenSSH host trust entries from a file, stdin or a server. |

The command pages document accepted inputs, destinations and fingerprint checks. A failed validation leaves the destination unchanged.

## Examples

Follow [Bifröst delegation](../../../authorization/bifroest.md) for a complete trust exchange, or the [SSH-environment example](../../../environment/ssh.md#openssh-certificate-authentication) to provision target trust.
