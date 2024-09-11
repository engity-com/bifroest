---
description: How sessions are stored within Bifröst and what they are for.
---

# Sessions

A session is grouping one or more connections of a user together. This enables the user:

1. ... to connect with several connections to the same [environment](../environment/index.md),
2. ... to use the same [environment](../environment/index.md), although all other prior connections are already disconnected, but the timeout of idle sessions is not already reached,
3. ... and the authorization _more lean_ by remembering the user by its [SSH Public Key](../data-type.md#ssh-public-key) instead of (for example of the [OpenID Connect Authorization](../authorization/oidc.md)) repeatedly asking the user to go through the authorization flow.

## Types

1. `fs`: [Filesystem](fs.md) (default type)

## Examples

1. Using [filesystem session](fs.md):
   ```yaml
   type: fs
   ```
