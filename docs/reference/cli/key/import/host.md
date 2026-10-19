---
description: Import trusted SSH host keys.
---

# `bifroest key import host`

Validates and merges normal `known_hosts` entries from a file, stdin, or an SSH server. Incoming `@revoked`, `@cert-authority`, and certificate entries are rejected. A fingerprint mismatch leaves the destination unchanged.

## Syntax

<<cli_syntax("key import host")>>

`--address` can contact an SSH server to obtain a host key. The imported trust file is local to the CLI machine.

## Arguments

None.

## Flags {: #key-import-host-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("knownHostsFile", "File Path", "../../../data-type.md#file-path", required=True, id_prefix="key-import-host-", heading=3)>>
OpenSSH `known_hosts` file to update.

<<flag("input", ref("File Path", "../../../data-type.md#file-path"), id_prefix="key-import-host-", heading=3)>>
File containing entries to import. `-` or omission reads from stdin. This cannot be combined with `address`. Input is limited to 4 MiB.

<<flag("address", "string", id_prefix="key-import-host-", heading=3)>>
SSH server from which one negotiated host key is retrieved. Port `22` can be omitted.

<<flag("expectedFingerprint", "string", id_prefix="key-import-host-", heading=3)>>
Expected OpenSSH SHA256 fingerprint, or `unknown`. It is required with `address`; omission for file or stdin input implies `unknown`.

!!! warning
     `--expectedFingerprint unknown` with `--address` explicitly trusts a key obtained from an unverified network peer and can expose the connection to an on-path attack. The command also emits a warning to stderr.

## Output

A local `known_hosts` file containing the successfully imported entries. Invalid entries and fingerprint mismatches leave the destination unchanged.

## Examples

### Import trusted entries exported by the server

1. Obtain the server's [`key export host`](../export/host.md) output through an independently trusted provisioning channel. It can contain several host keys.
2. Import those already trusted entries on the workstation:

    ```shell
    bifroest key import host \
      --knownHostsFile ~/.ssh/known_hosts \
      --input /srv/ssh-trust/bifroest-known-hosts
    ```

    The importing user needs write access to the destination's parent directory. For a single imported key, `--expectedFingerprint` can additionally check its independently retained fingerprint; one fingerprint cannot match several different keys. The [SSH-environment configuration](../../../environment/ssh.md#openssh-certificate-authentication) and [Bifröst delegation example](../../../authorization/bifroest.md) show complete trust exchanges. Use [Remote access](../../management.md) to configure a management alias after provisioning host trust.

## Availability

<<cli_availability()>>
