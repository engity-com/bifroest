---
description: Configure fail-closed SSH session recording, storage, delivery, and retention.
---

# Session recording

Session recording is disabled by default. Configure it under an [audit log](index.md) to capture one signed [asciicast v3](https://docs.asciinema.org/manual/asciicast/v3/) for each SSH shell or exec task. The audit journal itself may remain disabled.

## Properties

<<property("enabled", "bool", default=False)>>
Enables session recording for flows that reference this audit log. `auditlog.enabled` may remain `false`: Bifröst still uses the signing identity and Recording repository but creates **no audit journal**.

<<property("directory", "File Path", "../data-type.md#file-path", default="<os specific>")>>
Local recording repository. Keep it on an access-controlled filesystem, separate from session storage, audit journals and key files. Bifröst manages it exclusively; do not modify it or rotate its files externally.

The default depends on the operating system:

* Linux: `/var/lib/engity/bifroest/recordings`
* Windows: `C:\ProgramData\Engity\Bifroest\recordings`

The local filesystem is trusted; repository signatures do not protect against an operator or attacker who can alter managed paths concurrently.

<<property("compression", "Compression", "#compression")>>
Compression profile for recorded event chunks.

<<property("chunkSizeBytes", "uint64", None, default=262144)>>
Target chunk size before compression, from `1` to `1048577` bytes. An indivisible event group can exceed this target.

<<property("flushInterval", "Duration", "../data-type.md#duration", default="2s")>>
Maximum time between checkpoints while content is pending; must be positive.

<<property("flushSizeBytes", "uint64", None, default=1048576)>>
Pending output threshold for a checkpoint; must be positive.

<<property("maximumSpoolBytes", "uint64", None, default=107374182400)>>
Maximum local spool, including active and sealed recordings, receipts, and recovery work (default 100 GiB). Must be at least `chunkSizeBytes` and `flushSizeBytes`. If the spool is full, recording fails closed; startup never deletes evidence just to fit the limit.

<<property("retainFor", "Duration", "../data-type.md#duration", default="720h")>>
How long an eligible sealed recording remains locally (default 30 days). `0s` stops new automatic deletions but not one already begun. See [retention](#remote-delivery-and-retention).

<<property("notice", ref("String", "../templating/index.md#string"), default="")>>
Optional notice before an interactive PTY shell. It can use `{{.recording.id}}` and `{{.recording.startedAt}}`; Bifröst adds no newline. The notice becomes recorded output and does not appear for exec or non-PTY tasks. Do not rely on it as the only notice where policy requires one for those tasks.

<<property("targets", array_ref("Remote target", "remote-targets/index.md"), default="inherit")>>
Selects remote destinations for sealed recordings:

* `inherit` uses every target configured in the parent audit log.
* `false` disables remote recording delivery while leaving audit-log target delivery unchanged.
* A nonempty list defines independent recording targets using the same [S3, SFTP, and WebDAV schemas](remote-targets/index.md) as the audit log.

Every selected target is required. Settle outstanding delivery before changing destinations or disabling Recording; otherwise pending artifacts remain in the local spool. See [remote target behavior](remote-targets/index.md#delivery-behavior).

## Compression

<<property("level", "string", None, default="default", heading=3, id_prefix="compression-")>>
Compression profile for chunked Zstandard encoding. `default` is currently the only supported value.

## Captured data and privacy

* PTY tasks capture terminal output and resize events; non-PTY tasks capture stdout and stderr. SFTP and forwarding payloads are not recorded. A forced command is recorded as an exec task.
* Raw keyboard input is not captured. **Echoed commands and secrets printed by programs can still appear in the output.** Treat recordings and exported Casts as sensitive; encrypted containers also expose public metadata.
* Recording is terminal playback, not a byte-for-byte SSH capture. With the default `failurePolicy: strict`, a local recording failure aborts the affected task. With `bestEffort`, Bifröst disables the audit log and recording until restart. See [failure policy](index.md#property-failurePolicy).

## Recording-only

With `auditlog.enabled: false` and `recording.enabled: true`, Bifröst creates signed `.bcast` or `.becast` files and signed delivery receipts, but **no `.baudit`/`.beaudit` journal or audit events**. Lifecycle, delivery and retention audit events are not written. Recording failures still obey `failurePolicy`.

The repository binds its mode: switching between recording-only and audited recording requires a **new empty Recording directory**. Preserve the previous repository and evidence. Recording targets, including inherited targets, still receive sealed Recordings, but no audit segments.

## Formats and keys

Recording inherits its signing identity and optional age recipient from the parent audit log:

* Without `encryptionPublicKey` or `encryptionPublicKeyFile`, Bifröst stores signed, compressed native `.bcast` artifacts.
* With an encryption recipient, Bifröst stores signed CBOR `.becast` artifacts whose compressed event groups are independently encrypted with age.

Encrypted inspection without the private age key verifies only the signed outer envelope, **not** decrypted content or claimed status. Full export verifies the content. Even encrypted artifacts expose metadata such as recording ID and timing; protect them. See the [native format](../../formats/recording.md) and [test vectors](../../formats/recording-vectors.md) for wire details.

Switching between `.bcast` and `.becast`, or between recording-only and audited mode, requires a new empty Recording directory. If an audit journal is enabled, changing its recipient also requires a new empty audit-log directory. Preserve old evidence and decryption keys. If the signing key is lost, Bifröst refuses to regenerate it over existing history.

## Storage and recovery

* `active/` holds in-progress recordings; `sealed/` holds immutable `.bcast` or `.becast` files. Startup seals interrupted recordings as `incomplete`. Integrity failures in accepted evidence fail closed; there is no manual repair command.
* `quarantine/` and `.bifroest-work/` hold rejected and in-progress recovery work. Do not manually move these files into `sealed/`.
* `.delivery/` holds signed receipts. Only with an enabled audit journal does its `receipt.lifecycle` outbox hold signed, **unencrypted** flow names, correlation IDs and digests until the event is recorded. Recording-only has no lifecycle outbox. Protect the entire repository and its backups with filesystem permissions/ACLs; signatures protect integrity, not confidentiality.

With an enabled audit journal, recovery replays pending terminal audit events at least once; a crash after commit can produce an identical duplicate. Recording-only recovers the sealed artifact and its receipt **without** creating an audit event. See [recording lifecycle events](events.md#sessionrecordingincomplete).

## Remote delivery and retention

Signed receipts bind sealed bytes to selected remote targets. Delivery retries asynchronously; changing a target cannot redirect an outstanding artifact. See [remote delivery](remote-targets/index.md#delivery-behavior).

With targets, `retainFor` begins after the last durable acknowledgement; an enabled audit journal additionally requires success-audit markers. Without targets, it begins at sealing. Bifröst deletes only local recordings, not remote copies; set remote retention separately. `retainFor: 0s` stops new automatic deletions.

## Export and playback

* `recording export` verifies the signature and content before writing a full, **never redacted** Cast. Protect `session.cast` and open it with an [asciicast v3 player](https://docs.asciinema.org/manual/asciicast/v3/).
* Bifröst does not list, download or play recordings. Remote targets store only sealed originals, not plaintext Casts. For metadata without export, use [`recording inspect`](../cli/recording/inspect.md); see the [native format](../../formats/recording.md) for verification details.

## Examples

### Clear recording

1. Enable **recording only** on the `default` entry. Existing flows use `default` unless they select another audit log:

    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    auditlog:
      - enabled: false
        recording:
          enabled: true
    ```

2. Start Bifröst and use a shell or exec task. After it ends, find `<recording-uuid>.bcast` under `recording.directory/sealed/`. An optional [recording notice](#property-notice) shows the ID **only for interactive PTY shells**. Enable `auditlog.enabled: true` separately if you also need [audit events](events.md#sessionrecordingstarted) correlating it with the session.

3. On the **running** Bifröst host, export the already sealed `.bcast` to a file **outside** the repository. The local signing identity is used automatically; no configuration path or producer ID needs to be repeated:

    ```shell
    bifroest recording export \
      --auditlog default \
      --with-sensitive \
      --output session.cast \
      /var/lib/engity/bifroest/recordings/sealed/<recording-uuid>.bcast
    ```

### Encrypted recording

1. For a **new, empty** Recording directory, configure an [offline age recipient](index.md#encrypted-audit-events) on the parent entry. Bifröst then writes `.becast` instead of `.bcast` without creating an audit journal:

    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    auditlog:
      - enabled: false
        encryptionPublicKeyFile: /etc/engity/bifroest/audit-recipient.pub
        recording:
          enabled: true
    ```

2. On the Bifröst host, get the signing producer ID from the **local signing key** and transfer it independently to the offline workstation. Copy the already sealed `.becast` there **without stopping Bifröst**; do not copy the signing private key:

    ```shell
    bifroest audit producer-id default
    # Independently retain this 64-hex ID; do not take it from the .becast file.
    ```

3. On the offline workstation, decrypt and export the copied artifact. **The recipient's private key stays offline:**

    ```shell
    bifroest recording export \
      --expectedProducerId "<trusted-64-hex-producer-id>" \
      --decryptionIdentityFile /srv/audit-keys/recipient-key \
      --with-sensitive \
      --output session.cast \
      session.becast
    ```
