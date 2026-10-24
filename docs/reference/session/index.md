---
description: How sessions are stored within Bifröst and what they are for.
---

# Sessions

A session is grouping one or more connections of a user together. This enables the user:

1. ... to connect with several connections to the same [environment](../environment/index.md),
2. ... to use the same [environment](../environment/index.md), although all other prior connections are already disconnected, but the timeout of idle sessions is not already reached,
3. ... and the authorization _more lean_ by remembering the user by its [SSH Public Key](../data-type.md#ssh-public-key) instead of (for example of the [OpenID Connect Authorization](../authorization/oidc.md)) repeatedly asking the user to go through the authorization flow.

For OIDC, a remembered key can skip the browser step, but does not disable configured refresh-token checks or permit reuse of a disposed session.

The filesystem repository also provides [identity/target association selection](fs.md#session-association-groundwork), used by primary Simple, htpasswd, Local, verified OIDC device logins and authenticated Bifröst-delegation logins with built-in environments. Each connection retains its own verified claims and restrictions. The [HTTP authentication APIs](../connection/http.md#interactive-and-public-key-login-protocol) share verified session selection with SSH and issue separate scoped ephemeral web proofs after password, interactive/OIDC or key possession verification. Anonymous web-to-SSH resumption, browser RememberMe, frontend and a browser workspace remain pending.

## Types

1. `fs`: [Filesystem](fs.md) (default type)

## Examples

1. Using [filesystem session](fs.md):
   ```yaml
   type: fs
   ```
