---
description: Configure Bifröst's cryptographically verifiable audit log.
---

# Audit log

Defines named audit logs that Bifröst uses to record security-relevant actions separately from the regular application log. Each [flow](flow.md) references one of these entries by name.

If `auditlog` is omitted or empty, Bifröst creates an implicit entry named `default` that is disabled. While an entry is disabled, it does not create keys, directories, or network connections.

## Properties

<<property("name", "Audit log Name", default="default")>>
The unique name used by flows to reference this audit log. The implicit entry and an omitted name default to `default`.

<<property("enabled", "bool", default=False)>>
If `true`, Bifröst records security-relevant actions in the audit log.

Enabled audit logs must use distinct identity files and non-overlapping journal directories. Identity files must be outside every enabled journal directory.

<<property("identityFile", "File Path", "data-type.md#file-path", default="<os specific>")>>
Where the dedicated audit signing key is stored. If the file does not exist and the local journal does not contain history, an Ed25519 key will be created automatically.

If the key is missing while journal history exists, Bifröst will refuse to start instead of silently creating a new audit identity. An existing invalid key will not be replaced.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/auditlog-key`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog-key`

<<property("encryptionPublicKey", "SSH Public Key", "data-type.md#ssh-public-key")>>
Optional OpenSSH Ed25519 or RSA public key used to encrypt each audit event payload as an independent [age](https://age-encryption.org/) message. If neither this property nor `encryptionPublicKeyFile` is configured, event payloads are stored unencrypted. Structural metadata needed for recovery, signatures, hash chains, and segment verification remains visible, but the encrypted event is covered by the record signature and hash.

Exactly one public key is accepted. Keep its private key outside the Bifröst server and supply it only to offline audit commands through `--decryptionIdentityFile`. The encryption key must differ from every private key available to the server. Bifröst rejects reuse of host keys, audit signing keys, and statically configured SSH environment keys; operators must ensure dynamically rendered identity paths cannot resolve to the encryption key. Changing, adding, or removing the encryption recipient for a journal containing records is rejected; key rotation requires preserving old decryption identities and is not yet supported.

<<property("encryptionPublicKeyFile", ref("File Path", "data-type.md#file-path", ref("SSH Public Key", "data-type.md#ssh-public-key")))>>
Loads the single encryption public key from an OpenSSH public-key file when the enabled auditlog is initialized. This is an alternative to [`encryptionPublicKey`](#property-encryptionPublicKey); the two properties cannot be combined. The file must exist and contain exactly one supported public key without authorized-key options or certificates.

<<property("journal", "Journal", "#journal")>>
See [below](#journal).

<<property("targets", array_ref("Remote target", "#remote-targets"))>>
Optional destinations that receive complete sealed segments from the authoritative local journal. See [below](#remote-targets).

## Journal

The local journal is the authoritative, crash-safe source of the audit log. Remote targets replicate sealed journal segments and do not replace local persistence.

### Properties {: #journal-properties }

<<property("directory", "File Path", "data-type.md#file-path", default="<os specific>", heading=4, id_prefix="journal-")>>
Where the local audit journal and remote-delivery spool are stored. Bifröst manages this directory and its segment rotation; external log rotation tools must not modify it.

Bifröst holds an exclusive lock for the lifetime of the journal, so only one process can write a configured producer journal at a time. Each accepted record is signed with the dedicated Ed25519 identity, linked to the previous record, and flushed to stable storage before recording succeeds.

The journal rotates at approximately 16 MiB. Closed segments are signed, linked to the previous segment, published under a content-hash-bound name, and made read-only. A separately signed journal head anchors the latest accepted record, including records in the active segment.

On startup, Bifröst completes interrupted segment publication and discards only physically incomplete trailing frames. Invalid signatures, broken chains, loss of records behind the journal head, and complete malformed frames prevent startup instead of being ignored.

Use [`bifroest audit verify`](cli.md#audit-journals) for read-only offline verification. The related `audit export` and `audit merge` commands produce JSON Lines only after complete verification; these derived outputs are not themselves signed journals.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/auditlog`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog`

## Remote targets

Remote targets are named destinations for immutable sealed journal segments. They never receive the active segment and never replace synchronous local persistence.

!!! warning
     Remote delivery is not active in this build. Configuring targets on an enabled audit log currently makes Bifröst refuse to start instead of silently ignoring them. Delivery will become available with the remote-delivery coordinator.

Each target requires a unique `name` within its audit log and a `type`. The currently supported target type is `s3`.

### S3

The S3 target supports AWS S3 and HTTPS services implementing the required S3 SigV4 operations. A compatible service must honor conditional `PutObject` requests with `If-None-Match: *`, SHA-256 object checksums, and `GetObject`; verify these capabilities for services such as OVHcloud, MinIO, Ceph, or Wasabi before deployment. Each target has its own credentials; Bifröst does not use AWS profiles, container or instance metadata, web identity, or another default credential provider.

Every segment is uploaded with one conditional `PutObject` request. Multipart uploads are not used. If the object already exists, Bifröst reads it once and accepts it only when its size and SHA-256 checksum match. Existing conflicting content is never overwritten.

Objects use the key `<prefix>/<producer-id>/<sealed-segment-file>`, omitting `prefix` when it is empty.

#### Properties {: #s3-properties }

<<property("name", "string", required=True, id_prefix="s3-", heading=5)>>
The unique, path-safe name of this target within the audit log.

<<property("type", "string", default="s3", required=True, id_prefix="s3-", heading=5)>>
Selects the S3 target implementation. Type names are case-insensitive when read; Bifröst writes the canonical value `s3`.

<<property("bucket", "string", required=True, id_prefix="s3-", heading=5)>>
The destination bucket. It must follow the AWS general-purpose bucket naming rules.

<<property("region", "string", default="{{ env `AWS_REGION` | default (env `AWS_DEFAULT_REGION`) }}", id_prefix="s3-", heading=5)>>
The SigV4 signing region. This value supports Bifröst string templates without a context object. `AWS_REGION` takes precedence over `AWS_DEFAULT_REGION`; a non-empty result is required when the target is initialized.

<<property("prefix", "string", default="", id_prefix="s3-", heading=5)>>
An optional object-key prefix without a leading or trailing slash. Empty and relative path components are rejected.

<<property("endpoint", "URL", "data-type.md#url", id_prefix="s3-", heading=5)>>
An optional absolute HTTPS S3 endpoint without user information, path, query, or fragment. If omitted, the AWS S3 endpoint for `region` is used. Configure this property explicitly for another S3-compatible provider; AWS endpoint override environment variables are not used.

<<property("pathStyle", "bool", default=False, id_prefix="s3-", heading=5)>>
If `true`, addresses the bucket in the URL path instead of as a hostname. Enable this only when required by the selected S3-compatible service.

<<property("expectedBucketOwner", "string", id_prefix="s3-", heading=5)>>
Optional twelve-digit AWS account ID sent with both `PutObject` and conflict-checking `GetObject` requests. AWS rejects the request when the bucket belongs to another account. Omit this AWS-specific protection for services that do not support it.

<<property("accessKeyId", "string", default="{{ env `AWS_ACCESS_KEY_ID` | default (env `AWS_ACCESS_KEY`) }}", id_prefix="s3-", heading=5)>>
The target's access key ID. This value supports Bifröst string templates without a context object. `AWS_ACCESS_KEY_ID` takes precedence over the legacy alias `AWS_ACCESS_KEY`; a non-empty result is required. Configure this property and `secretAccessKey` together, or leave both at their defaults.

<<property("secretAccessKey", "string", default="{{ env `AWS_SECRET_ACCESS_KEY` | default (env `AWS_SECRET_KEY`) }}", id_prefix="s3-", heading=5)>>
The target's secret access key. This value supports Bifröst string templates without a context object. `AWS_SECRET_ACCESS_KEY` takes precedence over the legacy alias `AWS_SECRET_KEY`; a non-empty result is required. Configure this property and `accessKeyId` together. Prefer an environment variable or the `file` template function over storing the secret directly in YAML.

<<property("sessionToken", "string", default="{{ env `AWS_SESSION_TOKEN` }}", id_prefix="s3-", heading=5)>>
Optional session token for temporary credentials. This value supports Bifröst string templates without a context object. The `AWS_SESSION_TOKEN` default is used only while `accessKeyId` and `secretAccessKey` also use their defaults; custom credentials receive no session token unless a target-specific value or template is configured explicitly.

Template results for credentials are used exactly as rendered and are not trimmed. Secret files must therefore not contain an unintended trailing newline.

#### Permissions

The credentials need only these S3 actions on the configured bucket and prefix:

* `s3:PutObject` to publish a sealed segment conditionally.
* `s3:GetObject` to verify an object after a conditional-write conflict.

`s3:ListBucket`, `s3:DeleteObject`, and multipart-upload permissions are not required. When the bucket enforces SSE-KMS, its key policy may additionally require `kms:GenerateDataKey` for writes and `kms:Decrypt` for conflict verification.

## Examples

### Basic audit logs

```yaml
auditlog:
  - # name: default -> 'default' is the default name
    enabled: true

  - name: restricted
    enabled: true
    identityFile: /etc/engity/bifroest/auditlog-key
    journal:
      directory: /var/lib/engity/bifroest/auditlog
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
         --decryptionIdentityFile /etc/engity/bifroest/auditlog-key \
         my-auditlog
       ```

    2. Decrypt the journal:
       ```shell
       bifroest audit decrypt \
         --configuration /etc/engity/bifroest/configuration.yaml \
         --decryptionIdentityFile /etc/engity/bifroest/auditlog-key \
         --output /tmp/restricted-audit.jsonl \
         my-auditlog
       ```

        !!! note
            `audit decrypt` verifies the complete journal before publishing plaintext JSON Lines. Protect the output like any other sensitive audit data.

### AWS S3 target

With `AWS_REGION`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` set for the Bifröst process, the default templates keep the target concise:

```yaml
auditlog:
  - enabled: true
    targets:
      - name: aws-archive
        type: s3
        bucket: company-bifroest-audit
        prefix: bifroest-auditlog
        expectedBucketOwner: "123456789012"
```

### S3-compatible target with separate credentials

This OVHcloud-style example uses an explicit endpoint and target-specific credential sources. Other targets can reference different environment variables or files in the same way.

```yaml
auditlog:
  - enabled: true
    targets:
      - name: ovh-archive
        type: s3
        bucket: company-bifroest-audit
        region: gra
        endpoint: https://s3.gra.io.cloud.ovh.net
        accessKeyId: '{{ env `S3_ACCESS_KEY_ID` }}'
        secretAccessKey: '{{ env `S3_SECRET_ACCESS_KEY` }}'
```
