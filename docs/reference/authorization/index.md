---
description: Everything in Bifröst starts here. A user must be authorized at first. Bifröst supports types you can choose from to adjust to your needs.
---

# Authorizations

Everything in Bifröst starts here. Firstly, a user must be authorized. Bifröst supports [different types of authorizations](#types) you can choose from to adjust to your needs.

## Types

1. `local`: [Local](local.md)
2. `oidc`: [OpenID Connect (OIDC)](oidc.md)
3. `simple`: [Simple](simple.md)
4. `htpasswd`: [Htpasswd](htpasswd.md)
5. `bifroest`: [Bifröst delegation](bifroest.md)
6. `none`: [None](none.md)

## Principal mapping {: #principal-mapping}

All authorization types expose a common [authentication context](../context/authentication.md)
without changing their existing authorization-specific fields. Defaults are:

| Authorization | `.authentication.principal` |
| --- | --- |
| Local | Resolved account name |
| Simple | Matched entry name |
| Htpasswd | Successfully authenticated name |
| OIDC | Verified subject (`sub`) |
| Bifröst | Verified original identity attested by the delegation |
| None | `anonymous`, not an authenticated identity |

<<property("principal", "string", template_context="../context/authentication.md")>>
Optional template inside `authorization` that replaces the default principal.
It can use existing `.authorization.*` fields; `.authentication.principal` inside
this mapping refers to the default principal, not recursively to the mapping.
For example, an OIDC authorization can use
`principal: '{{ .authorization.idToken.email }}'` when the verified provider
claims and the installation's access policy make that email suitable.

An empty, unavailable or invalid mapped value fails when resolved. There is no
fallback to the unverified `.remote.user`. A mapping changes neither issuer nor
subject and cannot turn anonymous authorization into authenticated access;
`none` therefore does not accept a configured principal mapping.

Existing configurations without `principal` retain their previous target-account
templates and behavior. Adding this field does not itself change environment
account selection or enable an additional network endpoint.

## Examples

1. Using [local authorization](local.md):
   ```yaml
   type: local
   ```
2. Using [OpenID Connect DeviceAuth authorization](oidc.md#device-auth):
   ```yaml
   type: oidcDeviceAuth
   issuer: https://login.microsoftonline.com/my-great-tenant-uuid/v2.0
   clientId: my-great-client-uuid
   clientSecret: very-secret-secret
   scopes:
      - openid
      - email
      - profile
      - offline_access
   ```
3. Using [Simple DeviceAuth](simple.md):
   ```yaml
   type: simple
   entries:
     - name: foo
       password: plain:bar
   ```
