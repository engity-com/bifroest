---
description: How to access context information about a local user within Bifröst.
---

# Context Local User

Represents a local account on Linux or Windows. [Local authorization](../authorization/local.md) is Unix-only; a local account candidate is also available in the [Local Environment context](local-environment.md) on Windows.

## Properties

<<property("name", "string")>>

(User)name of the user.

<<property("displayName", "string")>>

The display name of the user: GECOS on Linux, or the local SAM full name on Windows.

<<property("uid", "UID", "../data-type.md#uid")>>

The local account's [UID](../data-type.md#uid).

<<property("gid", "GID", "../data-type.md#gid")>>

**Linux only.** Shortcut for [`group.gid`](#property-group).

<<property("group", "Local Group", "local-group.md")>>

**Linux only.** The primary group of the user.

<<property("groups", array_ref("Local Group", "local-group.md"))>>

The user's supplementary groups on Linux. On Windows, these are direct local alias memberships; there is no primary group.

<<property("gids", array_ref("GID", "../data-type.md#gid"))>>

Shortcut for [`groups.*.gid`](#property-groups): numeric IDs on Linux, local group SIDs on Windows.

<<property("managed", "bool or null")>>

`true` or `false` when the current flow has a [Local Environment](local-environment.md), including `.authorization.user` in that flow. Otherwise `null`.

<<property("shell", "string")>>

Linux: the account's configured [shell](https://en.wikipedia.org/wiki/Shell_(computing)). Windows: `COMSPEC`, falling back to `cmd.exe`.

<<property("homeDir", "string")>>

Linux: the account home directory. Windows: its actual profile directory; reading this field loads the profile if it does not yet exist and requires Bifröst to run as LocalSystem.
