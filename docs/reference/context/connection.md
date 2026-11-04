---
description: How to access context information about an user's connection within Bifröst.
---

# Context Connection

Read-only metadata of the **current incoming connection or logical HTTP request**,
not the downstream target environment. Connection-bound rendering contexts expose
this object as `.connection`. It is available before authorization; its presence
does not authenticate the peer or grant permissions.

For HTTP, metadata belongs to the current host/slug selection. Requests sharing
an HTTP/2 socket do not share or inherit another request's selection. Forwarded
headers, cookies and client JSON cannot override the transport or direct peer.

## Properties

<<property("id", "string")>>

The server-assigned connection UUID. It is not the persistent session ID or an
access token. The existing read-only `.connection.Id` spelling is also supported.

<<property("transport", "string")>>

`ssh` or `http`, selected by the trusted incoming adapter. For example:

```yaml
remoteName: '{{if eq .connection.transport "ssh"}}{{regexReplaceAll "@[^@]+$" .remote.user ""}}{{else}}{{.remote.user}}{{end}}'
```

Unknown explicit transports or invalid HTTP selections fail rendering instead
of being treated as SSH. Legacy SSH adapters without an explicit selection keep
their existing SSH default.

<<property("remote", "Remote", "remote.md")>>

The original requesting username and direct numeric peer IP address, without a
port. This is the same identity information as the surrounding `.remote`, not a mapped account
or authenticated principal. Existing `.connection.Remote.User` and
`.connection.Remote.Host` read-only spellings remain supported.

<<property("http", "object", optional=True)>>

Present for HTTP and null for SSH:

| Property | Meaning |
| --- | --- |
| `.connection.http.host` | Validated canonical incoming HTTP hostname, without its port. Not the target host or a forwarded-header value. |
| `.connection.http.slug` | Exact canonical slug for this request. Case-sensitive; empty for the root selection. |

The legacy read-only `.connection.Selection.Transport`,
`.connection.Selection.Host` and `.connection.Selection.Slug` spellings remain
supported through `.connection.Selection`.

The rendering view does not expose a socket, logger, lifetime/control methods,
HTTP headers, passwords, keys or bearer tokens. Core/startup and background
cleanup contexts without a current connection do not invent one. See the
[context availability overview](index.md#current-connection).
