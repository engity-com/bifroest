---
toc_depth: 4
description: How to authorize a requesting user via OpenID Connect (OIDC) with Bifröst.
---
# OpenID Connect (OIDC) authorization

Authorizes a requesting user via [OpenID Connect (OIDC)](https://openid.net/developers/how-connect-works/).

There is no need that the actual user exists in any way on the host machine of Bifröst. Even if the [local environment](../environment/local.md) is used together with [`createIfAbsent`](../environment/local.md#linux-property-createIfAbsent-evaluation) and [`updateIfDifferent`](../environment/local.md#linux-property-updateIfDifferent-evaluation) set to `true` it will create/update the users; therefore no need of tools like Puppet or Ansible are required.

As a result this enables in an easy way SSO for big, but also smaller organizations; see [use cases for more details](../../usecases.md).

Currently, there the following flow of OpenID Connect is supported:

* [Device Auth](#device-auth)

## Device Auth {: #device-auth }

### Properties {: #device-auth-properties }

<<property("type", "Authorization Type", default="oidc", required=True, id_prefix="device-auth-", heading=4)>>
Has to be set to `oidcDeviceAuth` to enable the OIDC DeviceAuth authorization.

<<property("issuer", "URL", None, id_prefix="device-auth-", heading=4, required=True)>>
The issuer is the URL identifier for the service which is issued by your identity provider.

##### Examples {: #device-auth-property-issuer-examples }
* `https://login.microsoftonline.com/my-great-tenant-uuid/v2.0`
* `https://accounts.google.com`
* `https://login.salesforce.com`

<<property("clientId", "string", None, id_prefix="device-auth-", heading=4, required=True)>>
Client ID issued by your identity provider.

<<property("clientSecret", "string", None, id_prefix="device-auth-", heading=4, required=True)>>
Secret for the corresponding [Client ID](#device-auth-property-clientId).

<<property_with_holder("scopes", "Array", None, "string", None, id_prefix="device-auth-", heading=4, required=True)>>
Scopes to request the token from the identity provider for.

##### Examples {: #device-auth-property-scopes-examples }
```yaml
scopes:
    - openid
    - email
    - profile
```

<<property("retrieveIdToken", "bool", None, id_prefix="device-auth-", default=True, heading=4)>>
Will retrieve the ID Token makes it available in the [corresponding context via `idToken`](../context/authorization.md#oidc-property-idToken).

<<property("retrieveUserInfo", "bool", None, id_prefix="device-auth-", default=False, heading=4)>>
Will retrieve the UserInfo makes it available in the [corresponding context via `userInfo`](../context/authorization.md#oidc-property-userInfo).

### Context {: #device-auth-context }

This authorization will produce a context of type [Authorization OIDC](../context/authorization.md#oidc).

### Examples {: #device-auth-examples }

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

## Compatibility

| [`linux`/`generic`](../../setup/distribution.md#linux-generic) | [`linux`/`extended`](../../setup/distribution.md#linux-extended) | [`windows`/`generic`](../../setup/distribution.md#windows-generic) |
| - | - | - |
| <<compatibility(True)>> | <<compatibility(True)>> | <<compatibility(True)>> |
