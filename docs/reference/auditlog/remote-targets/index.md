---
description: Replicate sealed Bifröst audit-log segments to remote storage.
---

# Remote targets

Remote targets copy complete, sealed audit-log segments to external storage. The local journal remains the authoritative, crash-safe source; remote targets provide additional independent retention and never receive the active segment.

Each target has a unique `name` within its audit log and selects one of the following implementations with `type`:

* [S3](s3.md) stores segments in AWS S3 or a compatible object store.
* [SFTP](sftp.md) stores segments on an SSH-authenticated SFTP server.
* [WebDAV](webdav.md) stores segments in an HTTPS WebDAV collection.

!!! warning
     Remote delivery is not active in this build. Configuring targets on an enabled audit log currently makes Bifröst refuse to start instead of silently ignoring them. Delivery will become available with the remote-delivery coordinator.
