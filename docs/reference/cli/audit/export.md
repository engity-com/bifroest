---
description: Verify and export a configured, copied or remotely selected audit journal as JSON Lines.
---

# `bifroest audit export`

Verifies the selected journal, then exports events as JSON Lines in journal order.

```shell
bifroest audit export default
```

## Syntax

<<cli_syntax("audit export", "[flags] [auditlogName]")>>

<<cli_syntax("audit export", "--source PATH --expectedProducerId ID [flags] [auditlogName]")>>

<<cli_syntax("audit export", "[flags] [auditlogName]", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

`auditlogName` selects a configured journal and defaults to `default` in the local CLI and integrated client. With `--source`, it labels the copied journal in exported records. It is not a segment path; a standalone delivered segment is not a complete journal source.

## Flags {: #audit-export-flags }

Includes [general executable flags](../index.md#general-flags). Direct SSH supports only the command options noted above.

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-export-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Cannot be combined with `--source` or `@target`.

<<flag("source", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Complete copied local journal, including its signed head and required segments. Requires independent producer trust; no server configuration or signing private key is needed. Unavailable with `@target`.

<<flag("encryptionPublicKeyFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Expected recipient for an encrypted offline `--source`. Required for keyless outer verification and when supplying multiple decryption identities. With one private key, its recipient can be derived instead. Unavailable with `@target`.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-export-", heading=3)>>
Local private key for encrypted confidential fields; repeatable. Used only with `--with-sensitive`. The client can use `X-AuditPrivateKey`; keys stay on the CLI machine. Unavailable over direct SSH.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Include confidential fields. Encrypted journals additionally need the matching decryption key. Without this flag, supplied private keys are not loaded for event decryption.

<<flag("expectedProducerId", "string", id_prefix="audit-export-", heading=3)>>
Independently trusted 64-hex signing producer ID. Configured local selection otherwise uses its signing key; copied sources require this flag. The integrated client requires it or `X-ExpectedProducerId`. Unavailable over direct SSH.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=3)>>
JSONL destination file, or `-` for stdout. The immediate parent must already exist. Named output is published only after successful verification and [destination checks](../verification.md#protected-destinations); remote-client paths are local to the workstation. Unavailable over direct SSH.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=3)>>
Replace an existing named output. Protected destinations remain protected. Unavailable over direct SSH.

## Output

One event with its origin and integrity metadata per JSON line. The default public event contains `name`, optional `domain` and `outcome`; `--with-sensitive` includes private fields. JSONL is an unsigned view of the original evidence. There is no `--format` selector.

Every selected source is verified before events are published. Events added during a live read may be absent from the result. Export has a **128 MiB JSONL output cap**; use [`audit verify`](verify.md) to verify a larger journal without exporting its events.

## Examples

### Export a configured journal

1. Enable and use [basic audit logging](../../auditlog/index.md#basic-audit-logs).
2. Export its public view:

    ```shell
    bifroest audit export default --output /srv/audit-evidence/public.jsonl
    ```

    Create the output directory beforehand and keep it outside managed storage.

### Export confidential encrypted events on a workstation

Follow [the encrypted-evidence guide](../../../guides/evidence.md) to configure the server, trusted producer and local recipient key, then run:

```shell
bifroest @bifroest-admin audit export evidence \
  --with-sensitive \
  --output /srv/audit-evidence/sensitive.jsonl
```

For disconnected verification, use a complete copied journal with `--source`, as shown in [the offline audit example](../../auditlog/index.md#encrypted-audit-events).

Also accepted as `audit decrypt`.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local invocation supports configured and copied journals. Client-side remote export requires `allowArtifactTransfer: true`, including for redacted exports, because it downloads original signed evidence.

Direct SSH accepts an explicit auditlog name and `--with-sensitive`, writes JSONL to stdout and uses the service's configured trust. Sensitive output requires artifact-transfer permission; encrypted private fields require a workstation's client-side decryption instead.
