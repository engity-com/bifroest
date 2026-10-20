---
description: Understand producer trust, verification scopes, key files and protected export destinations.
---

# Trust and verification

Audit and Recording commands verify signed evidence without changing its originals or creating a missing signing identity. Their reference pages specify whether they read a configured repository, a copied file or downloaded evidence.

## Trust a producer

A valid signature proves cryptographic consistency. To establish **who produced the evidence**, the verifier needs an independently trusted signing identity.

| Source | Trust anchor |
| --- | --- |
| Configured local repository | Its configured signing key; an explicit expected producer ID can replace it where supported. |
| Direct-SSH repository query | The running service's signing identity. |
| Copied or client-downloaded evidence | Independently obtained `--expectedProducerId`, or `X-ExpectedProducerId` for supported remote commands. |

The producer ID is a 64-hex identifier of the signing key. Obtain it from [`audit producer-id`](audit/producer-id.md) through an independently trusted channel and retain it separately. An ID or public key read only from the evidence is not a trust anchor. SSH host-key checking authenticates the connection and is distinct from producer trust.

`recording inspect` can report untrusted self-consistency explicitly. Recording export/play accept `--allowUntrusted` as an explicit alternative to producer trust; it cannot be combined with an expected producer ID. Normal verification requires trusted evidence.

## Outer and full verification

| Scope | What is verified |
| --- | --- |
| `outer` | Signed public metadata, structure and encrypted bytes; encrypted private content remains unverified. |
| `full` | The signed container and its decoded content, including decrypted content where applicable. |

Clear journals and Recordings can be fully verified without a decryption key. Encrypted evidence needs the matching recipient private key for full verification. `--require-full` makes a verification command fail rather than accepting outer-only verification.

Signing, SSH-login and encryption keys have different roles. The recipient private key belongs on the verification workstation; only its public key is configured on the server. An SSH authentication agent does not decrypt evidence. Follow [the encrypted-evidence guide](../../guides/evidence.md) for a complete setup.

## Key-file requirements

Loaded signing and decryption private keys must be regular, non-symlink files with exactly one hard link and a size of at most **1 MiB**:

* On Unix, the effective process user must own the file and group/other access must be absent.
* On Windows, the current process-token owner must own the file, with a protected DACL whose allow entries name only that owner, `OWNER RIGHTS`, or `SYSTEM`.

Configured local commands do not regenerate a missing signing key. For supported audit commands, an explicit trusted producer ID permits verification without opening that signing private key. Recording selection by local auditlog name instead uses its configured identity; copied-file and remote selectors accept external producer trust as documented.

## Complete evidence and live reads

An offline audit source needs the **complete journal**, including `<root>/<producer-id>/head.cbor`, all required sealed segments and any active segment. Remote delivery targets store sealed segments rather than a complete journal; a single delivered segment is not an audit CLI source. Recordings are independently sealed `.bcast` or `.becast` originals.

Audit commands can run while the service keeps writing. Events added during the operation may be absent from the result. When several journals are read, their results need not represent the same instant. A journal that changes during a read can cause an error and require a retry. Detecting rollback or deletion of recent history needs an independently retained record of the expected latest state in addition to signature verification.

Verification of large journals may require temporary disk space. Use a private temporary location outside the source repositories. An unsuitable or unwritable temporary location causes verification to fail. Treat files left after a forcibly interrupted verification as sensitive and remove them only after confirming that the operation has ended.

## Protected destinations

Export files must be outside managed journal, Recording and filesystem session-storage directories. Destination checks protect the loaded configuration, signing identities, referenced encryption public keys, SFTP known-hosts files and SFTP identities, as well as supplied decryption identities. They cover active configured entries beyond the selected sources, including Recording-only entries, and apply with `--force`.

Local metadata and configured evidence-output commands also protect statically configured SSH host keys and SSH-flow login/certificate/CA identities, together with known-hosts files, authorized-keys files and trusted user-CA files. The checks inspect file identities without loading or generating keys. Session-dependent file templates are not evaluated by metadata queries and cannot supply additional protected paths for that query.

The integrated management client also protects its SSH login identities, `known_hosts` files and the normal primary user and system SSH client configuration files from stdout redirection or use as an export destination. With `--sshConfig` (`-F`), it protects the selected primary configuration instead of the unused normal configuration files. Additional files referenced by `Include` are not automatically inventoried by this destination check.

Redirecting metadata to a separate regular file normally does not require listing unrelated repositories. Hard-linked outputs or ambiguous filesystem aliases can require an inventory check; insufficient access then causes the command to fail before writing. Reading the selected source still requires its normal permissions.

Named output requires an existing immediate parent directory. An existing destination is replaced only with a complete, verified result. Symbolic links, hard links and stdout redirection do not bypass protected-file checks where the alias can be detected; normal pipes remain supported.

A shell redirection using `>` can truncate its destination **before Bifröst starts**. Command-side checks cannot undo that truncation. Choose a separate destination, and use the command's `--output` option when saving an export. Protect managed paths against concurrent untrusted writers; the filesystem is part of the trusted boundary.

## Exported views

Audit JSON Lines are derived, unsigned views. By default, event fields contain only `name`, optional `domain` and `outcome`, accompanied by timestamps and origin metadata. A redacted export does not redact the underlying clear `.baudit` journal. Recording exports contain the full, never-redacted signed Cast. Even public metadata can be sensitive.

Preserve original signed evidence. See the [audit format](../../formats/audit.md), [Recording format](../../formats/recording.md) and [signed Cast format](../../formats/cast.md) for the cryptographic representations.
