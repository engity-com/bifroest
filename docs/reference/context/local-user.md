---
description: How to access context information about a local user within Bifröst.
---

# Context Local User

Represents a local user which is usually the resolve of the [Local authorization](../authorization/local.md).

## Properties

<<property("name", "string")>>

(User)name of the user.

<<property("displayName", "string")>>

The display name (or _title_ or [_GECOS_](https://en.wikipedia.org/wiki/Gecos_field)) of the user.

<<property("uid", "uint32")>>

The [_UID_ (user identifier)](https://en.wikipedia.org/wiki/User_identifier) of the user.

<<property("group", "Local Group", "local-group.md")>>

The primary group of the user.

<<property("gid", "uint32")>>

Shortcut for [`group.gid`](#property-group).

<<property_with_holder("groups", "Array", None, "Local Group", "local-group.md")>>

The groups (do not confuse with the [primary group](#property-group)) of the user.

<<property_with_holder("gids", "Array", None, "uint32")>>

Shortcut for [`groups.*.gid`](#property-groups).

<<property("shell", "string")>>

The used [shell](https://en.wikipedia.org/wiki/Shell_(computing)) of the user.

<<property("homeDir", "string")>>

The home directory of the user.
