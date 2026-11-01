---
description: How sessions are stored within Bifröst and what they are for.
---

# Sessions

A session groups a user's connections to the same [environment](../environment/index.md).
It lets the user:

1. Open several connections to one environment.
2. Reconnect to that environment while the session remains valid, even after all previous connections have closed.
3. Use a remembered SSH public key to avoid repeating an interactive login, where the authorization supports it.

For OIDC, a remembered key can skip the browser step, but does not disable configured refresh-token checks or permit reuse of a disposed session.

With filesystem sessions and built-in environments, fresh SSH and browser logins
can also [reuse a session by verified identity, flow and target](fs.md#session-association-groundwork).
Every connection retains its own checked credentials and restrictions; a known
session ID does not grant access.

[Browser RememberMe](../connection/http.md#rememberme) is a separate opt-in with
current authorization checks and an independent browser-key proof. Each new
terminal starts a fresh execution, not a reattachment. Closing a connection or
logging out of the browser is not session disposal; see [Browser access](../../guides/browser-access.md).

## Types

1. `fs`: [Filesystem](fs.md) (default type)

## Examples

1. Using [filesystem session](fs.md):
   ```yaml
   type: fs
   ```
