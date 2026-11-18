---
description: Everything in Bifröst starts here. A user must be authorized at first. Bifröst supports types you can choose from to adjust to your needs.
---

# Authorizations

Everything in Bifröst starts here. Firstly, a user must be authorized. Bifröst supports [different types of authorizations](#types) you can choose from to adjust to your needs.

Each [flow](../flow.md#property-authorization) selects one authorization, either inline or from the root [`authorizations` map](../configuration.md#property-authorizations). An omitted authorization uses `authorizations.default` only if defined.

## Types

1. `local`: [Local](local.md)
2. `oidcAuthorizationCode`: [OIDC Authorization Code](oidc/authorization-code.md)
3. `oidcDeviceAuth`: [OIDC Device Authorization](oidc/device-authorization.md)
4. `simple`: [Simple](simple.md)
5. `htpasswd`: [Htpasswd](htpasswd.md)
6. `bifroest`: [Bifröst delegation](bifroest.md)
7. `none`: [None](none.md)

The resulting identity is available through [Context Authentication](../context/authentication.md).

## Examples

1. Using [local authorization](local.md):
   ```yaml
   type: local
   rememberMe: allowedAndEnabledByDefault
   ```
2. Using [OpenID Connect Device Authorization](oidc/device-authorization.md):
   ```yaml
   type: oidcDeviceAuth
   rememberMe: allowedAndEnabledByDefault
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
   rememberMe: allowedAndEnabledByDefault
   entries:
     - name: foo
       password: plain:bar
   ```
