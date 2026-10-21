---
description: Verify and chronologically merge multiple configured or remotely selected audit journals.
---

# `bifroest audit merge`

Verifies every selected journal before producing one chronological JSON Lines stream.

```shell
bifroest audit merge workload administration
```

## Syntax

<<cli_syntax("audit merge", "[flags] <auditlogName>...")>>

<<cli_syntax("audit merge", "[flags] <auditlogName>...", remote=True)>>

## Arguments

### `auditlogName` {: #argument-auditlogName }

One or more required auditlog names. Local inputs can also be complete evidence copies referenced by a dedicated configuration. There is no `--source` flag on merge. When journals are still being written, their results need not represent the same instant.

## Flags {: #audit-merge-flags }

Includes [general executable flags](../index.md#general-flags).

<<flag("configuration", "File Path", "../../data-type.md#file-path", aliases=["c"], id_prefix="audit-merge-", heading=3)>>
Local repository configuration; defaults to the [platform path](../usage.md#configuration). Unavailable with `@target` or direct SSH.

<<flag("decryptionIdentityFile", "File Path", "../../data-type.md#file-path", id_prefix="audit-merge-", heading=3)>>
Local private key for encrypted confidential fields; repeat for different recipients. Keys are loaded only with `--with-sensitive`. The client can use `X-AuditPrivateKey`. Unavailable over direct SSH.

<<flag("with-sensitive", "bool", default=False, id_prefix="audit-merge-", heading=3)>>
Include private event fields. Every encrypted source then needs its matching private key.

<<flag("expectedProducerId", "string", id_prefix="audit-merge-", heading=3)>>
Trusted producer mapping `<auditlogName>=<64-hex-id>`; repeat for each independently trusted source. For one selected source, a plain producer ID is also accepted. Configured local sources otherwise use their signing identities. Remote multi-source merge needs explicit trust for every source; `X-ExpectedProducerId` supplies a default only when one source is selected. Unavailable over direct SSH.

<<flag("output", ref("File Path", "../../data-type.md#file-path"), default="-", id_prefix="audit-merge-", heading=3)>>
JSONL destination file or `-` for stdout. Its immediate parent must already exist. Named output is published only after successful verification and [destination checks](../verification.md#protected-destinations), including protection for unselected configured evidence. Client output paths are local to the workstation. Unavailable over direct SSH.

<<flag("force", "bool", default=False, id_prefix="audit-merge-", heading=3)>>
Replace an existing named output. Protected destinations remain protected. Unavailable over direct SSH.

## Output

JSON Lines ordered by producer-signed timestamp. Ordering is deterministic when timestamps are equal. A producer's timestamp is not an independently trusted clock. The public view is redacted; sensitive output is plaintext. JSONL is unsigned and there is no `--format` flag.

All sources must verify before output is published. The merged JSONL result is limited to **128 MiB**. See [Output and errors](../output.md).

## Examples

### Merge separately configured workload and administration logs

1. Configure the two logs and generate workload and administration connections using [the management guide](../../../guides/management.md).
2. On the host, export their public events in chronological order:

    ```shell
    bifroest audit merge workload administration --output /srv/audit-evidence/merged.jsonl
    ```

    The destination directory must already exist and remain outside managed storage.

### Merge complete offline copies without server signing keys

1. Retain each source's producer ID independently. Copy each **complete** journal to the verification machine.
2. Point a dedicated configuration at those copies:

    ```yaml title="Verification workstation: /srv/audit-evidence/configuration.yaml"
    auditlog:
      - name: first
        enabled: true
        identityFile: /srv/audit-evidence/absent-first-signing-key
        directory: /srv/audit-evidence/first-journal
      - name: second
        enabled: true
        identityFile: /srv/audit-evidence/absent-second-signing-key
        directory: /srv/audit-evidence/second-journal
    session:
      type: fs
      storage: /srv/audit-evidence/session-inspection
    flows:
      - name: evidence-inspection
        auditlog: first
        authorization:
          type: none
        environment:
          type: dummy
    ```

    This example selects clear journal copies. It is an inspection-only configuration, not a server setup. The placeholder signing-key files are intentionally absent.

3. Supply both independently retained IDs, replacing `FIRST_PRODUCER_ID` and `SECOND_PRODUCER_ID`:

    ```shell
    bifroest audit merge first second \
      --configuration /srv/audit-evidence/configuration.yaml \
      --expectedProducerId first=FIRST_PRODUCER_ID \
      --expectedProducerId second=SECOND_PRODUCER_ID \
      --output /srv/audit-output/merged.jsonl
    ```

    With explicit producer trust, the signing private keys are not opened or created. For encrypted copies, also configure each recipient public key, and supply local private keys with `--with-sensitive` when confidential fields are needed.

## Availability

<<cli_availability(remote=True, direct_ssh=True)>>

Client-side remote merge downloads the selected journals and requires `allowArtifactTransfer: true`.

Direct SSH accepts auditlog names and `--with-sensitive`, writes stdout and uses configured server trust. Sensitive output requires artifact-transfer permission. Use the integrated client for decrypting encrypted fields with workstation keys.
