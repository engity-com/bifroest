---
description: Choose an OpenID Connect login flow for SSH and browser access.
---

# OpenID Connect (OIDC) authorization

Authenticates users through an external [identity provider (IdP)](https://openid.net/developers/how-connect-works/). MFA and passkeys remain with the IdP; Bifröst's [environment](../../environment/index.md) determines where the session runs.

## Choose a flow

| | [Authorization Code](authorization-code.md) | [Device Authorization](device-authorization.md) |
| --- | --- | --- |
| Bifröst HTTP connection | Required, also for SSH | Not required for SSH |
| User experience | Familiar browser redirect; often simpler SSO | Separate verification page and code; potentially less convenient |
| IdP compatibility | Broad OIDC support | Requires explicit Device Authorization support |
| Login protection | PKCE S256, browser binding and explicit SSH approval | Device-code verification and approval at the IdP |

Authorization Code can offer security advantages with a suitable setup; neither flow is automatically safer. WebUI access requires HTTPS with either flow.

For a complete setup, see the [OIDC login guide](../../../guides/oidc.md).

## Examples

### Authorization Code {: #authorization-code }

Enable the [HTTP connection](../../connection/http/index.md) and register its `/login/callback` URL at the IdP.

```yaml
type: oidcAuthorizationCode
issuer: https://idp.example.org/realms/company
clientId: bifroest
clientSecret: YOUR_CLIENT_SECRET
scopes: [ openid, profile, offline_access ]
```

[Authorization Code properties and examples](authorization-code.md)

### Device Authorization {: #device-auth }

Enable Device Authorization for the IdP client. SSH does not need a Bifröst HTTP listener.

```yaml
type: oidcDeviceAuth
issuer: https://idp.example.org/realms/company
clientId: bifroest
clientSecret: YOUR_CLIENT_SECRET
scopes: [ openid, profile, offline_access ]
```

[Device Authorization properties and examples](device-authorization.md)

Both examples use the default refresh checks. The IdP must issue a refresh token; use the scopes and client settings required by your provider.
