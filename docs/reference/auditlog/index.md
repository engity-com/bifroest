---
description: Configure Bifröst's cryptographically verifiable audit log.
---

# Audit log

Defines named audit logs that Bifröst uses to record security-relevant actions separately from the regular application log. Each [flow](../flow.md) references one of these entries by name.

If `auditlog` is omitted or empty, Bifröst creates an implicit entry named `default` that is disabled. While an entry is disabled, it does not create keys, directories, or network connections.

## Properties

<<property("name", "Audit log Name", default="default")>>
The unique name used by flows to reference this audit log. The implicit entry and an omitted name default to `default`.

<<property("enabled", "bool", default=False)>>
If `true`, Bifröst records security-relevant actions in the audit log.

Enabled audit logs must use distinct identity files and non-overlapping journal directories. Identity files must be outside every enabled journal directory.

<<property("failurePolicy", "string", default="strict")>>
Controls what happens when this audit log or its session-recording repository fails:

* `strict` preserves fail-closed behavior. Initialization errors prevent startup, and runtime persistence errors abort the affected operation.
* `bestEffort` logs the first failure prominently, disables the complete audit log including session recording for the remainder of the process, and lets the service continue. It does not retry or automatically re-enable local persistence; restart Bifröst after correcting the cause.

Only `strict` and `bestEffort` are accepted. Remote-delivery outages continue to use their documented asynchronous retry behavior and do not by themselves disable the local audit log.

<<property("identityFile", "File Path", "../data-type.md#file-path", default="<os specific>")>>
Where the dedicated audit signing key is stored. If the file does not exist and the local journal does not contain history, an Ed25519 key will be created automatically.

If history exists, a missing or invalid key prevents startup. Existing keys must be regular, at most 1 MiB, owned by the Bifröst user, and neither symlinked nor hard-linked. Unix keys require mode `0400` or `0600`; Windows keys require a protected DACL limited to the owner, `SYSTEM`, and optionally `OWNER RIGHTS`.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/auditlog-key`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog-key`

<<property("encryptionPublicKey", "SSH Public Key", "../data-type.md#ssh-public-key")>>
Optional OpenSSH Ed25519 or RSA public key used to encrypt each event's confidential CBOR fields as an independent [age](https://age-encryption.org/) message. Without a recipient, Bifröst writes `.baudit`; with one, it writes `.beaudit`. The event name, domain, outcome, timestamp and verification metadata remain visible and signed in either format. Flow names, correlation IDs and the other [confidential event fields](native-format-contract.md#public-and-confidential-audit-fields) are compressed and encrypted only in `.beaudit`. Both formats contain these private fields in their original files, so restrict storage access regardless of extension.

Exactly one public key is accepted. Keep its private key outside the Bifröst server and supply it only to offline audit commands through `--decryptionIdentityFile`. The encryption key must differ from every private key available to the server. Bifröst rejects reuse of host keys, audit signing keys, statically configured SSH environment keys, and SFTP remote-target identity keys; operators must ensure dynamically rendered identity paths cannot resolve to the encryption key. Changing, adding, or removing the encryption recipient for a journal containing records is rejected; key rotation requires preserving old decryption identities and is not yet supported.

<<property("encryptionPublicKeyFile", ref("File Path", "../data-type.md#file-path", ref("SSH Public Key", "../data-type.md#ssh-public-key")))>>
Loads the single encryption public key from an OpenSSH public-key file when the enabled auditlog is initialized. This is an alternative to [`encryptionPublicKey`](#property-encryptionPublicKey); the two properties cannot be combined. The file must exist and contain exactly one supported public key without authorized-key options or certificates.

<<property("journal", "Journal", "#journal")>>
See [below](#journal).

<<property("recording", "Session recording", "recording.md")>>
Configures fail-closed shell and exec recording, local retention, and optional artifact delivery. Recording is disabled by default and requires this audit log to be enabled.

<<property("targets", array_ref("Remote target", "remote-targets/index.md"))>>
Optional destinations that receive complete sealed segments from the authoritative local journal. See [remote targets](remote-targets/index.md).

## Journal

The local journal is the authoritative, crash-safe source of the audit log. Remote targets replicate sealed journal segments and do not replace local persistence.

The configured local filesystem is part of Bifröst's trusted operating environment. Bifröst exclusively locks and manages its journal paths, but does not use owners, ACLs, link checks, or protection against concurrent external mutation as a security boundary. Use an access-controlled local filesystem and do not modify managed paths while Bifröst is running. Cryptographic signatures, hash chains, size limits, quotas, structural layout validation, and crash recovery remain enforced; links and other unsupported entries in managed repository locations can still be rejected as malformed state.

See [audit events](events.md) for the recorded security transitions, their structured fields, privacy guarantees, and failure behavior.

### Storage and recovery

Bifröst signs and durably flushes every accepted record. Native `.baudit` and `.beaudit` segments rotate at approximately 16 MiB and are linked through signed hashes; a signed `head.cbor` anchors the latest record. See the [native format contract](native-format-contract.md) for the public/private field boundary and container layout.

Startup repairs interrupted publication and uncommitted tails past the signed checkpoint, but rejects invalid committed units, signatures, broken chains, and lost records. Large scans use managed `.bifroest-work` directories, which can remain after an unclean process termination and may then be removed manually while Bifröst is stopped.

Use [`bifroest audit verify`](../cli/audit/verify.md) for read-only verification. The `export` and `merge` commands produce redacted JSON Lines by default only after verification; `--with-sensitive` explicitly includes the private fields and requires a decryption identity for `.beaudit`. These outputs are not signed journals.

### Properties {: #journal-properties }

<<property("directory", "File Path", "../data-type.md#file-path", default="<os specific>", heading=4, id_prefix="journal-")>>
Where the journal, delivery cursors, and temporary work data are stored. Bifröst locks and manages this directory exclusively; external log rotation tools must not modify it.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/auditlog`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog`

<<property("minimumFreeBytes", "uint64", None, default=268435456, heading=4, id_prefix="journal-")>>
The minimum filesystem space reserved from suppressible, unauthenticated audit records. Bifröst also accounts conservatively for the next record and journal-head replacement before allowing such a write. A configured value of `0` uses the secure default of 256 MiB rather than disabling the reserve.

Reaching this reserve suppresses only pre-authentication detail and aggregate records and emits one signed `journal-reserve` suppression marker while space is still reserved. A rate-limit aggregate that first detects the reserve keeps its original reason and outcome. Transition markers, that rate-limit aggregate, and final aggregate counts during orderly shutdown are bounded emergency writes that may consume the configured reserve. Failure of a final emergency write is returned as an incomplete audit flush while shutdown continues closing resources.

Successful or verified authentication and all later security events continue to use the normal synchronous, fail-closed recorder. Consequently, exhausting this threshold cannot itself lock out legitimate authentication. Other processes writing to the same filesystem and authenticated clients are outside this reserve's threat boundary; a dedicated filesystem remains recommended.

## Examples

### Basic audit logs

```yaml
auditlog:
  - # name: default -> 'default' is the default name
    enabled: true
    # failurePolicy: strict -> fail-closed is the default

  - name: restricted
    enabled: true
    failurePolicy: bestEffort
    identityFile: /etc/engity/bifroest/restricted-auditlog-key
    journal:
      directory: /var/lib/engity/bifroest/restricted-auditlog
      minimumFreeBytes: 268435456
```

### Encrypted audit events

1. On a trusted audit workstation, generate a dedicated Ed25519 keypair:
    ```shell
    bifroest key generate \
      --identityFile /etc/engity/bifroest/auditlog-key \
      --publicFile /etc/engity/bifroest/auditlog-key.pub
    ```
2. Transfer only the public file to the Bifröst server and reference it from the configuration:
    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    auditlog:
      - name: my-auditlog
        enabled: true
        encryptionPublicKeyFile: /etc/engity/bifroest/auditlog-key.pub
        identityFile: /etc/engity/bifroest/auditlog-signing-key
        journal:
          directory: /var/lib/engity/bifroest/auditlog
    ```
3. Ensure Bifröst is **NOT** running.

4. Now you can do the following things:

    1. Verify the journal:
       ```shell
       bifroest audit verify \
         --configuration /etc/engity/bifroest/configuration.yaml \
          my-auditlog
       ```

    2. Decrypt the journal:
       ```shell
       bifroest audit decrypt \
         --configuration /etc/engity/bifroest/configuration.yaml \
          --with-sensitive \
          --decryptionIdentityFile /etc/engity/bifroest/auditlog-key \
         --output /tmp/restricted-audit.jsonl \
         my-auditlog
       ```

        !!! note
            `audit decrypt` is an alias for `audit export`; without `--with-sensitive` it also writes only redacted JSON Lines. A sensitive export verifies and decrypts the private fields before publishing plaintext. Protect the output like any other sensitive audit data.
