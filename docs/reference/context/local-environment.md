---
description: Template context used by the local environment.
---

# Context Local Environment

Used by the [local environment](../environment/local.md) when evaluating account-management templates.

## Properties

Includes the [Authorization Request context](authorization-request.md), plus:

<<property("user", "Local User", "local-user.md", optional=True)>>

The [Local User](local-user.md) candidate, or null if none is available.
