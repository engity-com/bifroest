---
description: How to store Bifröst sessions on the local filesystem.
---

# Filesystem session

This variant of [session](index.md) is stored on the same local filesystem where also Bifröst is running.

## Properties

<<property("type", "Session Type", default="fs")>>
Can be set to `fs` to enable the filesystem session. If absent, `fs` is always chosen by default.

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="30m")>>
For how long a session can be idle before it will forcibly be closed and disposed and can therefore not be used again. This can extend by actions of the client (regular interactions or keep alive) across all of client's connections.

<<property("maxTimeout", "Duration", "../data-type.md#duration", default=0)>>
The maximum duration of a session before it will forcibly be closed and disposed regardless whether there are actions or not.

<<property("maxConnections", "uint16", "../data-type.md#duration", default=0)>>
The maximum amount of parallel connections of one session. Each new connecting connection will be instantly closed.

<<property("storage", "File Path", "../data-type.md#file-path", default='<os specific>')>>
Where the session information is stored locally.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/sessions`
* Window: `C:\ProgramData\Engity\Bifroest\sessions`

<<property("fileMode", "File Mode", "../data-type.md#file-mode", default="0600")>>
All files/directories inside the session storage will be stored with this mode. Directories will always get the executable bit.

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |

