---
description: Everything in Bifröst starts here. A user is required to be authorized at first. Bifröst supports types, you can choose from to adjust to your needs.
---

# Authorizations

Everything in Bifröst starts here. A user is required to be authorized at first. Bifröst supports [different types of authorizations](#types), you can choose from to adjust to your needs.

## Types

1. `local`: [Local](local.md)
2. `oidc`: [OpenID Connect (OIDC)](oidc.md)
3. `simple`: [Simple](simple.md)
4. `htpasswd`: [Htpasswd](htpasswd.md)

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
   ```
3. Using [Simple DeviceAuth](simple.md):
   ```yaml
   type: simple
   entries:
     - name: foo
       password: plain:bar
   ```
