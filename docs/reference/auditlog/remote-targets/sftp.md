---
description: Configure an SFTP remote target for sealed audit-log segments.
---

# SFTP

The SFTP target stores sealed segments below an existing absolute directory. Bifröst creates one child directory per producer and writes files as `<directory>/<producer-id>/<sealed-segment-file>`. The server must support the OpenSSH `hardlink@openssh.com` extension.

## Properties

<<property("name", "string", required=True, heading=3)>>
The unique, path-safe name of this target within the audit log.

<<property("type", "string", default="sftp", required=True, heading=3)>>
Selects the SFTP target implementation. Type names are case-insensitive when read; Bifröst writes the canonical value `sftp`.

<<property("publishAttemptTimeout", "duration", default="2m", heading=3)>>
Positive deadline for hashing, connection, upload, read-back check and hard-link publication. On cancellation Bifröst closes the SSH connection. If an upload or link may have happened, it opens one fresh connection for **one cleanup attempt**, separately limited to five seconds. Failed cleanup remains retryable by deterministic temporary-file name.

<<property("address", "string", required=True, heading=3)>>
The SSH server as `host`, `host:port`, or `[IPv6-address]:port`. An omitted port defaults to `22`.

<<property("user", "string", required=True, heading=3)>>
The SSH user. This value supports Bifröst string templates without a context object and must render to a non-empty value without control characters.

<<property("directory", "string", required=True, heading=3)>>
The existing absolute POSIX path on the SFTP server. Empty and relative path components are rejected. `/` is valid when the SFTP account is confined to an appropriate server-side root.

<<property("knownHosts", "string", heading=3)>>
Inline OpenSSH `known_hosts` entries used to verify the server host key.

<<property("knownHostsFile", "File Path", "../../data-type.md#file-path", heading=3)>>
Explicit OpenSSH `known_hosts` file (maximum 16 MiB). Bifröst never reads user or system files implicitly. It can be combined with `knownHosts`; changes require a target restart.

<<property("acceptAllHostKeys", "bool", default=False, heading=3)>>
Disables server host-key verification. This cannot be combined with `knownHosts` or `knownHostsFile` and should only be used in controlled test environments.

!!! warning
     Setting `acceptAllHostKeys: true` makes the target connection vulnerable to on-path attacks.

<<property("identityFiles", "list of File Paths", heading=3)>>
One or more unencrypted OpenSSH or PEM private keys, tried in order. Paths are static, not templates; keys must differ from audit signing and encryption keys. Files must be regular, owned by the Bifröst user and at most 1 MiB:

* Unix: no group or other access.
* Windows: protected DACL allowing only the owner and `SYSTEM`.

<<property("password", "string", default="", heading=3)>>
The SSH password. This value supports Bifröst string templates without a context object. Prefer an environment variable or the `file` template function over storing it directly in YAML. Template results are used exactly as rendered and are not trimmed.

Exactly one authentication method is required: either `password` or at least one `identityFiles` entry.

<<property("connectTimeout", "duration", default="10s", heading=3)>>
TCP, SSH and SFTP setup timeout. `0s` disables this **additional** limit; negative values are rejected. The earlier of this and `publishAttemptTimeout` wins.

## Delivery identity

Host-key trust binds to inline `knownHosts` **entries**, `knownHostsFile` **contents** (not its path), and the `acceptAllHostKeys` setting. Changing trust under the same target name rejects an existing cursor or outstanding Recording receipt. Moving an unchanged file does not; SSH credentials may rotate without changing the destination identity.

This fingerprint differs from the earlier unreleased format. Existing development cursors and pending receipts are not migrated. Settle them with the previous build or use a new empty repository while retaining old artifacts; merely renaming a target does not discharge pending receipts.

## Publication

* Upload to a deterministic hidden temporary name, verify its bytes, then publish with `hardlink@openssh.com` version `1`. **No rename or overwrite.** The server must also support permission changes via `SETSTAT` and `FSETSTAT`.
* Producer directories use mode `0700`, temporary files `0600`. An existing final file is accepted only if permissions, size and SHA-256 match.
* Retries reuse a verified temporary file. Only an invalid temporary file with the known deterministic name is removed before a later retry; conflicting final content is never replaced.

## Permissions

The SFTP account needs to inspect the root; create producer directories; set directory and temporary-file modes; and exclusively create, write, read, hard-link and delete temporary files. It does **not** need listing, final-file deletion, overwrite or rename permissions. Restrict it to the configured directory where possible.

## Example

```yaml
auditlog:
  - enabled: true
    targets:
      - name: sftp-archive
        type: sftp
        address: sftp.example.com:22
        user: audit-writer
        directory: /srv/audit/bifroest
        knownHostsFile: /etc/engity/bifroest/archive-known_hosts
        identityFiles:
          - /etc/engity/bifroest/archive-key
```
