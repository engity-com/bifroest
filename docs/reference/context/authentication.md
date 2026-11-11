---
description: Access a normalized authentication principal without confusing the requesting name with the authenticated identity.
---

# Context Authentication

`.authentication` provides a common identity view for authorizations. The original requesting name remains in `.remote.user`; authorization-specific fields remain in `.authorization`.

Missing identity information causes an error, not a fallback to the requesting name. During environment acceptance this context describes a candidate; accessing it does not itself prove successful authentication.

## Properties

<<property("principal", "string")>>
The actor's name or identifier, with these defaults:

| Authorization | Default principal |
| --- | --- |
| Local | Resolved account name |
| Simple | Matched entry name |
| Htpasswd | Authenticated name |
| OIDC | Verified subject (`sub`) |
| Bifröst | Attested original identity |
| None | `anonymous` (not authenticated) |

<<property("issuer", "string")>>
The authority that scopes `subject`: the verified OIDC issuer, the local authorization namespace, or the originating CA and authorization kind for Bifröst delegation.

<<property("subject", "string")>>
The identity within that authority: UID/SID for Local, the matched entry for Simple, the authenticated name for Htpasswd, and verified `sub` for OIDC. Bifröst delegation uses the attested original name, not an original OIDC subject.

<<property("isAuthenticated", "bool")>>
Whether an authenticated subject is available. `none` has empty issuer/subject and `isAuthenticated: false`; it cannot establish a shared authenticated identity.

## Principal mapping {: #principal-mapping}

The optional `authorization.principal` template changes the principal, not the issuer, subject or credentials being checked. It can use `.authorization.*`; `.authentication.principal` within that template refers to the default above. `none` does not accept this setting.

The result must be nonempty UTF-8, at most 1,024 bytes, without control characters. Invalid or unavailable values reject the operation. A principal is not automatically an allowed target account: configure the environment's account selection separately.

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
