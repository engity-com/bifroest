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
Maximum duration of one publication attempt, including local hashing, connection setup, upload, read-back verification, and hard-link publication. The value must be positive. Bifröst applies the deadline to the underlying SSH connection and closes that connection on cancellation. If a temporary file may have been created, a hard link succeeded, or the final file already exists, Bifröst opens one fresh connection and makes one deletion attempt with a separate context bounded to five seconds. A cleanup failure remains retryable; the deterministic name lets the next attempt find and remove the same temporary file.

<<property("address", "string", required=True, heading=3)>>
The SSH server as `host`, `host:port`, or `[IPv6-address]:port`. An omitted port defaults to `22`.

<<property("user", "string", required=True, heading=3)>>
The SSH user. This value supports Bifröst string templates without a context object and must render to a non-empty value without control characters.

<<property("directory", "string", required=True, heading=3)>>
The existing absolute POSIX path on the SFTP server. Empty and relative path components are rejected. `/` is valid when the SFTP account is confined to an appropriate server-side root.

<<property("knownHosts", "string", heading=3)>>
Inline OpenSSH `known_hosts` entries used to verify the server host key.

<<property("knownHostsFile", "File Path", "../../data-type.md#file-path", heading=3)>>
An explicit OpenSSH `known_hosts` file used to verify the server host key. Bifröst never implicitly reads user or system `known_hosts` files. `knownHosts` and `knownHostsFile` can be used together.

<<property("acceptAllHostKeys", "bool", default=False, heading=3)>>
Disables server host-key verification. This cannot be combined with `knownHosts` or `knownHostsFile` and should only be used in controlled test environments.

!!! warning
     Setting `acceptAllHostKeys: true` makes the target connection vulnerable to on-path attacks.

<<property("identityFiles", "list of File Paths", heading=3)>>
One or more unencrypted OpenSSH or PEM private-key files, tried in order. Each file must be regular, owned by the Bifröst process user, and at most 1 MiB. On Unix, group and other permission bits must all be disabled. On Windows, the file must use a protected DACL granting access only to its owner and `SYSTEM`. Identity paths are static and do not support templates. Their keys must differ from every configured audit-encryption recipient.

<<property("password", "string", default="", heading=3)>>
The SSH password. This value supports Bifröst string templates without a context object. Prefer an environment variable or the `file` template function over storing it directly in YAML. Template results are used exactly as rendered and are not trimmed.

Exactly one authentication method is required: either `password` or at least one `identityFiles` entry.

<<property("connectTimeout", "duration", default="10s", heading=3)>>
The maximum time allowed for TCP connection, SSH handshake, and SFTP session setup. A value of zero disables this additional timeout; negative values are rejected. The earlier deadline of `connectTimeout` and `publishAttemptTimeout` applies during setup.

## Publication

Bifröst uploads each segment under a deterministic hidden temporary name, verifies it, and exposes it atomically through a hard link. Temporary files use mode `0600` and producer directories mode `0700`; existing final files are accepted only when permissions, size, and SHA-256 checksum match.

Retries can resume a verified temporary file and remove it after publication. If an interrupted process leaves an invalid deterministic temporary file, Bifröst removes only that known file and retries the upload later. Conflicting final content is never overwritten. The server must support `hardlink@openssh.com` version `1` plus permission changes through `SETSTAT` and `FSETSTAT`; rename is intentionally not used.

## Permissions

The SFTP account needs permission to inspect the configured directory, create producer directories, change producer-directory and temporary-file modes, and exclusively create, write, read, hard-link, and delete temporary files below them. It does not need permission to list directories, overwrite final files, rename files, or delete final files. Restrict the account to the configured directory whenever the server supports path-scoped authorization.

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
