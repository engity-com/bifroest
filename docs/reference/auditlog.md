---
description: Configure Bifröst's cryptographically verifiable audit log.
---

# Audit log

Defines how Bifröst records security-relevant actions separately from the regular application log.

The audit log is disabled by default. While disabled, it does not create keys, directories, or network connections.

## Properties

<<property("enabled", "bool", default=False)>>
If `true`, Bifröst records security-relevant actions in the audit log.

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

### Configuration {: #journal-configuration }

<<property("directory", "File Path", "data-type.md#file-path", default="<os specific>", heading=4, id_prefix="journal-")>>
Where the local audit journal and remote-delivery spool are stored. Bifröst manages this directory and its segment rotation; external log rotation tools must not modify it.

Bifröst allows only one running process to own a journal and flushes every accepted record to durable storage. On startup, an incomplete trailing write is discarded safely; complete structural corruption prevents startup instead of being ignored.

Bifröst holds an exclusive lock for the lifetime of the journal, so only one process can write a configured producer journal at a time. Each accepted record is flushed to stable storage before recording succeeds. On startup, an incomplete trailing write is discarded safely; complete malformed records cause startup to fail.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/auditlog`
* Windows: `C:\ProgramData\Engity\Bifroest\auditlog`

## Example

```yaml
auditlog:
  enabled: true
```
