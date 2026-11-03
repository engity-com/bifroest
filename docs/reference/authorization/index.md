---
description: Everything in Bifröst starts here. A user must be authorized at first. Bifröst supports types you can choose from to adjust to your needs.
---

# Authorizations

Everything in Bifröst starts here. Firstly, a user must be authorized. Bifröst supports [different types of authorizations](#types) you can choose from to adjust to your needs.

Each [flow](../flow.md#property-authorization) selects exactly one authorization:
an inline object with `type` and its settings, or a name from the root
[`authorizations` map](../configuration.md#property-authorizations). Omitted,
`null` or empty values use `authorizations.default` only if explicitly defined;
otherwise an authorization is required. This is not a list of login providers
or a multi-authorization/MFA chain.

## Types

1. `local`: [Local](local.md)
2. `oidcDeviceAuth`: [OpenID Connect (OIDC)](oidc.md)
3. `simple`: [Simple](simple.md)
4. `htpasswd`: [Htpasswd](htpasswd.md)
5. `bifroest`: [Bifröst delegation](bifroest.md)
6. `none`: [None](none.md)

## Principal mapping {: #principal-mapping}

Built-in authorizations provide a common [authentication context](../context/authentication.md)
when the required identity information is available. Their authorization-specific fields remain unchanged. Default principals are:

| Authorization | `.authentication.principal` |
| --- | --- |
| Local | Resolved account name |
| Simple | Matched entry name |
| Htpasswd | Successfully authenticated name |
| OIDC | Verified subject (`sub`) |
| Bifröst | Verified original identity attested by the delegation |
| None | `anonymous`, not an authenticated identity |

<<property("principal", "string", template_context="../context/authorization.md")>>
Optional template inside `authorization` that replaces the default principal.
It can use existing `.authorization.*` fields; `.authentication.principal` inside
this mapping refers to the default principal, not recursively to the mapping.
A mapping that resolves to an empty, unavailable or invalid value fails. There is no
fallback to the unverified `.remote.user`. A mapping changes neither issuer nor
subject and cannot turn anonymous authorization into authenticated access;
`none` therefore does not accept a configured principal mapping.

The principal is not automatically a target account. Configure account selection
separately; see the [mapping example](../context/authentication.md#examples).
Use only identity claims whose assignment and verification policy you trust.
A signed email claim alone does not prove email ownership or permission to use
an account. Adding `principal` does not change existing target-account templates.

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
3. Using [Simple authorization](simple.md):
   ```yaml
   type: simple
   entries:
     - name: foo
       password: plain:bar
   ```
