---
description: Rendering context for current environment requests and tasks.
---

# Context Environment

Used while accepting, preparing or executing an environment for a current
incoming connection. Preparation and task variants inherit these properties.

## Properties

<<property("connection", "Connection", "connection.md")>>

Read-only incoming connection metadata. A browser connection remains `http` even
when the downstream environment uses SSH or a container.

<<property("remote", "Remote", "remote.md")>>

Original requesting username and direct peer, unchanged by `remoteName`.

<<property("authentication", "Authentication", "authentication.md")>>

Current normalized candidate identity; environment acceptance does not replace
credential verification or imply that authorization has already completed.

<<property("authorization", "Authorization", "authorization.md")>>

Current authorization candidate/result, retaining its existing type-specific
properties and restrictions.

<<property("session", "Session")>>

The associated session when available. Prospective target-resolution contexts
retain their existing restricted session reference; connection metadata does not
expand access to mutable session state.
