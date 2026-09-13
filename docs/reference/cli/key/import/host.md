---
description: Import trusted SSH host keys.
---

# `bifroest key import host`

Validates and atomically merges normal `known_hosts` entries from a file, stdin, or an SSH server. Incoming `@revoked`, `@cert-authority`, and certificate entries are rejected. Concurrent merge operations are locked, and any fingerprint mismatch leaves the destination unchanged.

## Syntax

`bifroest key import host [flags]`

## Flags {: #key-import-host-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("knownHostsFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-import-host-", heading=3)>>
OpenSSH `known_hosts` file to update.

<<flag("input", ref("File Path", "../../../data-type.md#file-path"), id_prefix="key-import-host-", heading=3)>>
File containing entries to import. `-` or omission reads from stdin. This cannot be combined with `address`.

<<flag("address", "string", id_prefix="key-import-host-", heading=3)>>
SSH server from which one negotiated host key is retrieved. Port `22` can be omitted.

<<flag("expectedFingerprint", "string", id_prefix="key-import-host-", heading=3)>>
Expected OpenSSH SHA256 fingerprint, or `unknown`. It is required with `address`; omission for file or stdin input implies `unknown`.

!!! warning
     `--expectedFingerprint unknown` with `--address` explicitly trusts a key obtained from an unverified network peer and can expose the connection to an on-path attack. The command also emits a warning to stderr.

## Examples

See the host-key bootstrap examples for [SSH environments](../../../environment/ssh.md#openssh-certificate-authentication) and [Bifröst delegation](../../../authorization/bifroest.md).
