---
description: How to access context information about a local group within Bifröst.
---

# Context Local Group

Represents a local group on Linux or a local alias on Windows. Linux groups may be resolved by [Local authorization](../authorization/local.md); Windows local aliases are available through the [Local Environment context](local-environment.md).

## Properties

<<property("name", "string")>>

The group name on Linux, or the local alias name on Windows.

<<property("gid", "GID", "../data-type.md#gid")>>

The group's [GID](../data-type.md#gid): a numeric group ID on Linux, or a textual local alias SID on Windows.
