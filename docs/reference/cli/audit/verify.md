---
description: Verify a configured, copied or remotely selected signed audit journal without exporting events.
---

# `bifroest audit verify`

Checks journal integrity and trusted producer identity without exporting events.

```shell
bifroest audit verify default
```

## Syntax

<<cli_syntax("audit verify", "[flags] [auditlogName]")>>

<<cli_syntax("audit verify", "--source PATH --expectedProducerId ID [flags] [auditlogName]")>>

<<cli_syntax("audit verify", "[flags] [auditlogName]", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

`auditlogName` selects a configured audit log and defaults to `default` locally and through `@target`. With `--source`, it labels the copied source rather than selecting a directory. Direct SSH requires the name explicitly.

## Flags {: #audit-verify-flags }

Includes [general executable flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-verify-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Cannot be combined with `--source` or `@target`; unavailable over direct SSH.

<<flag("source", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Complete local journal copy, including its signed head and required segments. Requires an independently trusted producer ID. Unavailable with `@target` or direct SSH.

<<flag("encryptionPublicKeyFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Expected recipient for an encrypted offline `--source`. Required without a private key or with multiple decryption identities. With one private key, the recipient can be derived instead. Unavailable with `@target` or direct SSH.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-verify-", heading=3)>>
Local private key for full verification of encrypted private fields; repeatable. The client can use `X-AuditPrivateKey`. Without a key, encrypted verification has outer scope; a supplied non-matching key fails. Unavailable over direct SSH.

<<flag("require-full", "bool", default=False, id_prefix="audit-verify-", heading=3)>>
Reject outer-only results. Available in all supported execution modes; direct SSH cannot fully verify encrypted content without a local recipient key, so that combination fails.

<<flag("expectedProducerId", "string", id_prefix="audit-verify-", heading=3)>>
Independent 64-hex signing producer ID. Configured local selection otherwise uses its signing key. Required for a copied source or provided through `X-ExpectedProducerId` for the client. Unavailable over direct SSH.

<<flag("format", "string", default="table", id_prefix="audit-verify-", heading=3)>>
Result format: `table`, `json`, `yaml` or `cbor`.

## Output

The default status is `verified (scope: outer)` or `verified (scope: full)`. Structured formats contain the verification result and scope. Success exits with status `0`; a verification failure produces no success result.

The command can run while the service keeps writing; later events may be absent from the verified result. A standalone delivered segment is not a complete journal source. See [verification scopes and evidence completeness](../verification.md).

## Examples

### Verify the configured journal while Bifröst runs

1. Enable [basic audit logging](../../auditlog/index.md#basic-audit-logs) and generate an SSH connection.
2. On the host, run as the service user:

    ```shell
    bifroest audit verify default
    ```

### Require full verification of encrypted remote evidence

1. Configure the recipient, producer pin and local private key using [the workstation guide](../../../guides/evidence.md).
2. Verify without exporting event content:

    ```shell
    bifroest @bifroest-admin audit verify evidence --require-full --format=json
    ```

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Local invocation supports configured and copied journals. Client-side remote verification downloads the journal and requires `allowArtifactTransfer: true`, including outer-only verification.

Direct SSH accepts an explicit auditlog name, `--require-full` and `--format`. It verifies server-side evidence without downloading it or accepting a workstation decryption key. No artifact-transfer permission is needed for that verification.
