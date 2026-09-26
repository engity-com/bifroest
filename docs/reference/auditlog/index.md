---
description: Configure Bifröst's cryptographically verifiable audit log.
---

# Audit log

Defines named audit logs that Bifröst uses to record security-relevant actions separately from the regular application log. Each [flow](../flow.md) references one of these entries by name.

If `auditlog` is omitted or empty, Bifröst creates a disabled `default` entry. With both audit logging and recording disabled, no signing key, journal, Recording repository or delivery connection is created. Recording can be enabled independently, without an audit journal.

## Properties

<<property("name", "Audit log Name", default="default")>>
The unique name used by flows to reference this audit log. The implicit entry and an omitted name default to `default`.

<<property("enabled", "bool", default=False)>>
Enables the audit journal and security events. Set `recording.enabled: true` independently to record sessions **without** an audit journal or audit events.

Enabled audit logs must use distinct identity files and non-overlapping journal directories. Identity files must be outside every enabled journal directory.

<<property("failurePolicy", "string", default="strict")>>
Controls what happens when this audit log or its session-recording repository fails:

* `strict` preserves fail-closed behavior. Initialization errors prevent startup, and runtime persistence errors abort the affected operation.
* `bestEffort` logs the first failure, disables this audit log and its recording until restart, but lets the SSH operation continue. Fix the cause and restart Bifröst; persistence does not automatically recover.

Only `strict` and `bestEffort` are accepted. Remote-delivery outages continue to use their documented asynchronous retry behavior and do not by themselves disable the local audit log.

<<property("identityFile", "File Path", "../data-type.md#file-path", default="<os specific>")>>
Signing key for the journal and/or Recording. Bifröst creates an Ed25519 key when an enabled journal or Recording needs one and neither repository contains prior state.

If history exists, a missing or invalid signing key prevents startup. Existing keys must be regular, at most 1 MiB, owned by the Bifröst user, and neither symlinked nor hard-linked:

* Unix: mode `0400` or `0600`.
* Windows: a protected DACL limited to the owner, `SYSTEM`, and optionally `OWNER RIGHTS`.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/auditlog-key`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog-key`

<<property("directory", "File Path", "../data-type.md#file-path", default="<os specific>")>>
Local audit-log directory. It contains the journal, delivery cursors, and temporary work data. Bifröst manages it exclusively; do not modify or rotate its files externally.

The platform defaults are:

* Linux: `/var/lib/engity/bifroest/auditlog`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog`

<<property("minimumFreeBytes", "uint64", None, default=268435456)>>
Filesystem space reserved for authenticated and other essential audit events. `0` uses the secure default of 256 MiB rather than disabling the reserve.

When the reserve is reached, Bifröst suppresses pre-authentication detail and counts it in bounded aggregates. A signed `journal-reserve` marker and pending/final aggregates may still use the emergency reserve. Authenticated events remain synchronous and fail closed; a dedicated filesystem is recommended because other processes can consume the reserved space.

<<property("encryptionPublicKey", "SSH Public Key", "../data-type.md#ssh-public-key")>>
Optional OpenSSH Ed25519 or RSA **public** age recipient key, also used by Recording. For an enabled audit journal, Bifröst encrypts confidential fields independently for each event:

* No recipient: signed `.baudit`; private fields are readable after decompression.
* With a recipient: signed `.beaudit`; private fields are compressed and encrypted. Only `name`, optional `domain` and `outcome`, plus signed envelope data such as time, record ID, chain and producer remain visible. See the [exact field boundary](../../formats/audit.md#public-and-confidential-audit-fields).

With recording alone, the same recipient selects `.becast`; no `.beaudit` journal is created.

!!! warning "Encryption does not cover all local state"
     A [Recording lifecycle outbox](recording.md#storage-and-recovery) can contain signed, **unencrypted** flow and correlation data even with `.beaudit`. Protect the entire Recording repository and its backups.

Use exactly one recipient and **keep its private key offline**. It must differ from all server keys, including host, signing, static SSH-environment and SFTP keys; also check dynamically rendered identity paths. A journal with records cannot change recipients: use a new empty journal and retain the old private key for its evidence.

<<property("encryptionPublicKeyFile", ref("File Path", "../data-type.md#file-path", ref("SSH Public Key", "../data-type.md#ssh-public-key")))>>
Loads the single encryption public key from an OpenSSH public-key file when the enabled auditlog is initialized. This is an alternative to [`encryptionPublicKey`](#property-encryptionPublicKey); the two properties cannot be combined. The file must exist and contain exactly one supported public key without authorized-key options or certificates.

<<property("recording", "Session recording", "recording.md")>>
Configures fail-closed shell and exec recording, local retention, and optional artifact delivery. Recording is disabled by default but can run without the audit journal. See [Recording-only](recording.md#recording-only).

<<property("targets", array_ref("Remote target", "remote-targets/index.md"))>>
Optional destinations for sealed audit segments. Recording may inherit these targets even when the journal is disabled; then only sealed Recordings are delivered. See [remote targets](remote-targets/index.md).

## Journal

The local journal is the authoritative, crash-safe source of the audit log. Remote targets replicate sealed journal segments and do not replace local persistence.

Use an access-controlled local filesystem and do not modify managed paths while Bifröst runs. The filesystem is **trusted**: owners, ACLs and link checks are not Bifröst's defense against concurrent external mutation. Signatures, chains, quotas, structural validation and crash recovery still apply; unsupported links can be rejected as invalid repository state.

See [audit events](events.md) for the recorded security transitions, their structured fields, privacy guarantees, and failure behavior.

### Storage and recovery

* Records are signed and flushed. `.baudit` and `.beaudit` segments rotate around 16 MiB; signed hashes link them to `head.cbor` under `<auditlog-directory>/<producer-id>/`. See the [format](../../formats/audit.md) and [vectors](../../formats/audit-vectors.md).
* Startup repairs uncommitted tails but rejects invalid committed data and lost records. Large recovery scans can leave `.bifroest-work` after a crash; remove stale work only while Bifröst is stopped. Read-only verification uses an OS temporary directory instead.
* [`audit export`](../cli/audit/export.md), [`audit verify`](../cli/audit/verify.md) and merge can read while Bifröst runs. They verify the **signed committed state**; later writes are not part of that result. Locally, export and verify use the default configuration and the selected auditlog name. Offline, both accept a complete journal copy through `--source` and an independently trusted `--expectedProducerId` without a configuration.
* Export and merge verify before writing redacted, **unsigned** JSONL. `--with-sensitive` includes private fields and needs the offline decryption key for `.beaudit`.
* Remote targets deliver **only sealed segments**, never the signed head or active file. A single downloaded segment is not verifiable as a complete journal. Keep the full journal and an independently trusted chain tip to detect a missing remote suffix.

## Examples

### Basic audit logs

1. Enable the `default` audit log of Bifröst:

    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    auditlog:
      - ## 'default' is the default name
        # name: default
        enabled: true
        ## Writes the auditlog into this directory by default
        # directory: /var/lib/engity/bifroest/auditlog
    flows:
      - name: foo
        ## 'default' auditlog is used by default
        # auditlog: default

        # ...
    ```

2. Start and use Bifröst...

    !!! note ""
         Bifröst writes unencrypted event segments named `*.baudit` to the [default auditlog directory](#property-directory). The directory also contains signed `head.cbor` and other managed state; retain the **whole journal** for verification.

3. Read the recorded events of Bifröst:
    ```shell
    bifroest audit export default

    # Verified, redacted JSONL from a signed checkpoint on stdout.
    ```

    !!! warning ""
         The exported JSONL is an unsigned view, not a substitute for the signed journal. Even redacted metadata needs protection; the clear `.baudit` files also contain confidential fields after decompression. To include those fields, explicitly add [`--with-sensitive`](../cli/audit/export.md#audit-export-flag-with-sensitive) to `audit export` and protect its plaintext output.

    To check the journal without JSONL, use [`audit verify`](../cli/audit/verify.md): `bifroest audit verify default`. It reports outer or full verification on success.

### Encrypted audit events

1. On an offline and trustworthy workstation, generate the recipient key pair:

    ```shell
    bifroest key generate \
      --identityFile /srv/audit-keys/recipient-key \
      --publicFile   /srv/audit-keys/recipient-key.pub
    ```
    !!! warning ""
         `/srv/audit-keys/recipient-key` should never reach Bifröst. It is only for the recipient, to be able to decrypt the auditlog, if needed.

2. Transfer **only** the public key to Bifröst's host: `/etc/engity/bifroest/audit-recipient.pub`

3. Configure Bifröst:

    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    auditlog:
      - enabled: true
        encryptionPublicKeyFile: /etc/engity/bifroest/audit-recipient.pub
        # Only for a NEW empty journal; existing .baudit history cannot switch.
        # Bifröst creates /etc/engity/bifroest/auditlog-key on first start.
    flows:
      - name: foo
        # ...
    ```

4. Start and use Bifröst.

    !!! note ""
         Bifröst creates the signing identity and journal automatically when they contain no history. It writes encrypted `.beaudit` segments; signed outer metadata remains visible.

5. Read events, redacted:

    ```shell
    bifroest audit export default

    # Redacted JSONL from a signed checkpoint; private fields stay encrypted.
    ```

6. Or, fully decrypted:

    1. On the Bifröst host, obtain the producer ID from the server's **signing key** and retain it through a trusted channel:

        ```shell
        bifroest audit producer-id \
           default
        # Save this 64-hex value independently;
        # never derive it from the journal.
        ```

    2. For a stable **complete evidence copy**, stop Bifröst and copy `/var/lib/engity/bifroest/auditlog` to `/srv/audit-evidence/auditlog` on the offline workstation. Day-to-day redacted reading in step 5 does not require a stop.

        !!! note ""
             Keep `head.cbor`, all sealed segments and any `active.beaudit` together. Remote targets only contain sealed segments and cannot replace this copy.

    3. Export confidential events on the offline workstation. No configuration file or server signing key is needed:

        ```shell title="Offline workstation"
        bifroest audit export \
          --source /srv/audit-evidence/auditlog \
          --expectedProducerId "<64-hex-producer-id>" \
          --decryptionIdentityFile /srv/audit-keys/recipient-key \
          --with-sensitive \
          --output /srv/audit-evidence/sensitive.jsonl
        ```

        !!! warning ""
             The decrypted JSONL is unsigned and not encrypted and must be protected like sensitive data.

        To verify without exporting events, use `bifroest audit verify --source /srv/audit-evidence/auditlog --expectedProducerId "<64-hex-producer-id>" --decryptionIdentityFile /srv/audit-keys/recipient-key --require-full`. Without the private key, encrypted journals can only be verified at outer scope. The offline auditlog label defaults to `default`.
