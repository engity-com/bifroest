---
description: Rendering context for current environment requests and tasks.
---

# Context Environment

Used while accepting, preparing or executing an environment.

## Properties

<<property("connection", "Connection", "connection.md")>>

The incoming connection.

<<property("remote", "Remote", "remote.md")>>

The requesting peer and original username.

<<property("authentication", "Authentication", "authentication.md")>>

The current authentication candidate.

<<property("authorization", "Authorization", "authorization.md")>>

The authorization candidate or result.

<<property("session", "Session")>>

The associated session, when available.
