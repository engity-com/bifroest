---
description: How to access context information about an user's connection within Bifröst.
---

# Context Connection

Information about the incoming connection, available as `.connection`.

## Properties

<<property("id", "string")>>

The connection UUID, distinct from the session ID.

<<property("transport", "string")>>

Incoming transport: `ssh` or `http`.

<<property("remote", "Remote", "remote.md")>>

The requesting username and direct peer IP address.

<<property("http", "object", optional=True)>>

Present for HTTP and null for SSH:

| Property | Meaning |
| --- | --- |
| `.connection.http.host` | Incoming HTTP hostname, without its port. |
| `.connection.http.slug` | Selected slug, case-sensitive; empty for the root. |
