---
description: How to store Bifröst sessions on the local filesystem.
---

# Filesystem session

This variant of [session](index.md) is stored on the same local filesystem on which Bifröst is running.

## Properties

<<property("type", "Session Type", default="fs")>>
Can be set to `fs` to enable the filesystem session. If absent, `fs` is always chosen by default.

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="30m")>>
How long a session may remain idle before access expires. Activity across its connections extends this time. Browser transport keepalive does not count as session activity. `0` disables this timeout. [Housekeeping](../housekeeping.md) disposes expired sessions.

<<property("maxTimeout", "Duration", "../data-type.md#duration", default=0)>>
Maximum lifetime from session creation, regardless of activity. Access ends at expiry. `0` disables this timeout.

<<property("maxConnections", "uint16", default=0)>>
Maximum concurrent connections per session, shared by SSH, browser terminals and management operations. Excess connections are rejected. `0` disables this limit.

<<property("storage", "File Path", "../data-type.md#file-path", default='<os specific>')>>
Where the session information is stored locally.

Only one Bifröst process can use a filesystem session repository at a time. Startup fails if the repository is already in use or exclusive access cannot be established.

A shared volume does not turn this repository into a multi-writer session backend. Locks are not distributed fencing; see [availability and recovery limits](../../setup/operations.md#high-availability-current-limits) before planning a replacement instance.

The storage must not overlap a configured audit log's journal, signing identity, encryption public-key file, or local SFTP target `known_hosts` and identity files. Unsafe paths are rejected during startup.

Private runtime key/state files are stored beside the resolved storage directory; immutable ownership (`ro`) and revocation (`rr`) records are stored with each session. Include them in a consistent, stopped backup. An unfinished runtime-pending marker blocks startup rather than guessing which authority or revocation survived. Do not delete runtime files to bypass recovery checks. See the [restart contract and recovery boundary](../../setup/upgrade.md#subsequent-restarts-and-runtime-metadata).

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/sessions`
* macOS: `/Library/Application Support/Engity/Bifroest/sessions`
* Windows: `C:\ProgramData\Engity\Bifroest\sessions`

<<property("fileMode", "File Mode", "../data-type.md#file-mode", default="0600")>>
Ordinary session metadata uses this mode. Directories also get the executable bit. Private ownership, revocation and runtime key/state files use restricted owner-only permissions independently of this setting.

## Examples

Limit concurrent connections and bound both idle and total session lifetime:

```yaml
type: fs
idleTimeout: 30m
maxTimeout: 8h
maxConnections: 4
```

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
