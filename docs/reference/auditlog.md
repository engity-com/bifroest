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

<<property("journal", "Journal", "#journal")>>
See [below](#journal).

## Journal

The local journal is the authoritative, crash-safe source of the audit log. Remote targets replicate sealed journal segments and do not replace local persistence.

### Properties {: #journal-properties }

<<property("directory", "File Path", "data-type.md#file-path", default="<os specific>", heading=4, id_prefix="journal-")>>
Where the local audit journal and remote-delivery spool are stored. Bifröst manages this directory and its segment rotation; external log rotation tools must not modify it.

Bifröst holds an exclusive lock for the lifetime of the journal, so only one process can write a configured producer journal at a time. Each accepted record is signed with the dedicated Ed25519 identity, linked to the previous record, and flushed to stable storage before recording succeeds.

The journal rotates at approximately 16 MiB. Closed segments are signed, linked to the previous segment, published under a content-hash-bound name, and made read-only. A separately signed journal head anchors the latest accepted record, including records in the active segment.

On startup, Bifröst completes interrupted segment publication and discards only physically incomplete trailing frames. Invalid signatures, broken chains, loss of records behind the journal head, and complete malformed frames prevent startup instead of being ignored.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/auditlog`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog`

## Example

```yaml
auditlog:
  - # name: default -> 'default' is the default name
    enabled: true

  - name: restricted
    enabled: true
    identityFile: /etc/engity/bifroest/restricted-auditlog-key
    journal:
      directory: /var/lib/engity/bifroest/restricted-auditlog
```
