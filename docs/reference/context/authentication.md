---
description: Access a normalized authentication principal without confusing the requesting name with the authenticated identity.
---

# Context Authentication

`.authentication` is the normalized identity view used by environment templates
and RememberMe notifications. Existing `.authorization.*` fields remain available
for authorization-specific information.

## Properties

<<property("principal", "string")>>
The resolved actor's configurable name, email address or other identifier. It is
not necessarily an operating-system account name, immutable, or globally unique.
Use the [authorization principal mapping](../authorization/index.md#principal-mapping)
when the default is unsuitable for a target account.

<<property("issuer", "string")>>
The authority that scopes `subject`. For OIDC this is the verified issuer.
Other built-in authorizations use a local authorization namespace; these
identities must additionally be scoped to the flow and effective target.

<<property("subject", "string")>>
The authority-scoped subject, independent of the principal mapping. Local
accounts use the UID on Unix or SID on Windows, Simple uses the matched entry,
and htpasswd uses the authenticated name. OIDC uses the verified `sub`.
Bifröst delegation v1 scopes the attested original name to the originating CA
and authorization kind; it does not invent an original OIDC issuer/subject pair
that the v1 evidence does not contain.

<<property("isAuthenticated", "bool")>>
Whether an authenticated subject is available. `authorization.type: none` has
principal `anonymous`, empty issuer/subject, and `isAuthenticated: false`.
Anonymous labels are never a basis for sharing sessions.

## Requesting name and target account

`.remote.user` remains the original client-supplied requesting name. Resolving a
principal never overwrites it. Required identity information that is unavailable
causes an error when `.authentication` is accessed, rather than substituting
`.remote.user`. OIDC configurations that retrieve neither verified ID-token
identity nor suitable UserInfo cannot provide this normalized identity unless a
previously verified identity is available in the managed session state.

During environment acceptance checks this context describes the authorization
candidate. Reading it does not by itself prove successful authentication: the
normal credential verification and authorization decision still have to succeed.

The target account remains separately configurable through `local.name`/`uid`,
`ssh.user`, or Docker/Kubernetes `user`. For example:

```yaml
environment:
  type: local
  name: '{{ .authentication.principal }}'
```

Choosing a target account is an access-policy decision, not identity verification.
An empty or invalid required mapping must not select a different account.
