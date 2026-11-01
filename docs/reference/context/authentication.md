---
description: Access a normalized authentication principal without confusing the requesting name with the authenticated identity.
---

# Context Authentication

`.authentication` is the normalized identity view used by environment templates
and RememberMe notifications. Existing `.authorization.*` fields remain available
for authorization-specific information.

It does not replace the original client-supplied requesting name in `.remote.user`.
Missing required identity information causes an error when this context is
accessed; `.remote.user` is never a fallback. OIDC needs verified identity
information from an ID token, suitable UserInfo or retained session state.

## Properties

<<property("principal", "string")>>
The actor's configurable name, email address or other identifier. It is not
necessarily an operating-system account name, immutable, or globally unique.
Use the [authorization principal mapping](../authorization/index.md#principal-mapping)
to change it. A mapped principal must be non-empty UTF-8, at most 1024 bytes,
and contain no control characters.

<<property("issuer", "string")>>
The authority that scopes `subject`: the verified OIDC issuer, a local
authorization namespace, or the originating CA and authorization kind for
Bifröst delegation. Session matching additionally checks the flow and target.

<<property("subject", "string")>>
The authority-scoped subject, independent of the principal mapping. Local
accounts use the UID on Unix or SID on Windows, Simple uses the matched entry,
and htpasswd uses the authenticated name. OIDC uses the verified `sub`.
[Bifröst delegation](../authorization/bifroest.md) uses the attested original name,
not an inferred original OIDC subject.

<<property("isAuthenticated", "bool")>>
Whether an authenticated subject is available. `authorization.type: none` has
principal `anonymous`, empty issuer/subject, and `isAuthenticated: false`.
Anonymous labels are never a basis for sharing sessions.

During environment acceptance checks this context describes the authorization
candidate. Reading it does not by itself prove successful authentication: the
normal credential verification and authorization decision still have to succeed.

The target account is configured separately through local `name`/`uid`, SSH `user`,
or Docker/Kubernetes `user`. Choosing it is an access-policy decision: an OIDC
subject or email address is not automatically an allowed account name.

## Examples

Use the verified local account name as the principal and select that same account
by name and UID/SID:

```yaml
flows:
  - name: local
    authorization:
      type: local
      principal: '{{ .authorization.user.name }}'
    environment:
      type: local
      name: '{{ .authentication.principal }}'
      uid: '{{ .authorization.user.uid }}'
```
