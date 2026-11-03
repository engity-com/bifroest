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

The storage must not overlap a configured audit log's journal, signing identity, encryption public-key file, or local SFTP target `known_hosts` and identity files. Unsafe paths are rejected during startup.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/sessions`
* macOS: `/Library/Application Support/Engity/Bifroest/sessions`
* Windows: `C:\ProgramData\Engity\Bifroest\sessions`

<<property("fileMode", "File Mode", "../data-type.md#file-mode", default="0600")>>
All files/directories inside the session storage will be stored with this mode. Directories will always get the executable bit.

## Session reuse {: #session-association-groundwork }

With built-in environments, Simple, htpasswd, Local, verified OIDC and authenticated
Bifröst-delegation logins can reuse a valid session for the same verified identity,
flow and effective target. Identity means issuer and subject, not a configurable
principal or the client-supplied requesting name. Anonymous logins are not merged
by identity.

Every connection must pass current credential, authorization and environment
checks. It keeps its own claims and PTY/forwarding restrictions. Reuse does not
bypass quotas, expiry or revocation. A session ID or matching association is not
a credential. See the additional [OIDC grant checks](../authorization/oidc.md#session-sharing)
and [browser security limits](../connection/http/security.md).

Target selection does not provision resources. Use deterministic, side-effect-free
target templates. They may read `.session.id`, `.session.flow`, `.session.created.*`
and their `.authorization.session.*` equivalents. Mutable session state and
last-access fields are rejected. A name such as `bifroest-{{ .session.id }}` is
evaluated against each existing candidate session, so it can select the same Pod.
Immutable client metadata is still not proof of identity; account mappings must
use verified identity or an explicit access policy.

Legacy sessions without association metadata remain usable through existing
remembered-key paths after possession and authorization checks. Fresh primary
logins do not automatically claim or migrate them. Third-party environments and
repositories without association support retain their existing SSH behavior.

Invalid or unknown association metadata stops selection in the affected flow and
is preserved for operator inspection. Corrupt legacy entries without an association
are skipped, not deleted. Do not remove metadata to bypass failed selection:
a container or Pod may still exist outside the session directory. Before downgrading, review the
[session-storage precautions](../../setup/upgrade.md#session-storage).

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
