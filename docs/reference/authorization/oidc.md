---
toc_depth: 4
description: How to authorize a user request via OpenID Connect (OIDC) with Bifröst.
---
# OpenID Connect (OIDC) authorization

Authorizes a user request via [OpenID Connect (OIDC)](https://openid.net/developers/how-connect-works/).

There is no need that the actual user exists in any way on the host machine of Bifröst. Even if the [local environment](../environment/local.md) is used together with [`createIfAbsent`](../environment/local.md#property-createIfAbsent) and [`updateIfDifferent`](../environment/local.md#property-updateIfDifferent) set to `true`, it will create/update the users. There is no need for tools like Puppet or Ansible.

This provides an easy way for SSO in all types of organizations, small or big. See [use cases for more details](../../usecases.md).

Currently, the following flow of OpenID Connect is supported:

* [Device Auth](#device-auth)

## Device Auth {: #device-auth }

### Properties {: #device-auth-properties }

<<property("type", "Authorization Type", default="oidc", required=True, id_prefix="device-auth-", heading=4)>>
Has to be set to `oidcDeviceAuth` to enable the OIDC DeviceAuth authorization.

<<property("issuer", "URL", "../data-type.md#url", template_context="../context/core.md", id_prefix="device-auth-", heading=4, required=True)>>
The issuer is the URL identifier for the service which is issued by your identity provider.

The issuer and its discovered device-authorization and token endpoints must use HTTPS. Bifröst rejects HTTP endpoints before transmitting client credentials. Private certificate authorities can be added to Bifröst's bundled trust store through the standard `SSL_CERT_FILE` environment variable.

##### Examples {: #device-auth-property-issuer-examples }
* `https://login.microsoftonline.com/my-great-tenant-uuid/v2.0`
* `https://accounts.google.com`
* `https://login.salesforce.com`

<<property("clientId", "string", template_context="../context/core.md", id_prefix="device-auth-", heading=4, required=True)>>
Client ID issued by your identity provider.

<<property("clientSecret", "string", template_context="../context/core.md", id_prefix="device-auth-", heading=4, required=True)>>
Secret for the corresponding [Client ID](#device-auth-property-clientId).

The provider metadata must support client-secret authentication at the token endpoint. Bifröst prefers `client_secret_basic`, falls back to `client_secret_post` when explicitly advertised, and uses the OpenID Connect default `client_secret_basic` when `token_endpoint_auth_methods_supported` is omitted. Providers that advertise neither method are rejected.

Redirects from the device-authorization and token endpoints are followed only when the destination has the same scheme and host as the configured endpoint. Cross-origin redirects are returned without being followed so that neither an Authorization header nor a `client_secret_post` request body can be forwarded to another origin.

<<property("scopes", array_ref("string"), template_context="../context/core.md", id_prefix="device-auth-", heading=4, default=["openid","profile","email"])>>
Scopes to request the token from the identity provider for.

For refresh-token verification, configure the scopes and client settings required by your provider to issue a refresh token (often `offline_access`). The default scopes (`openid`, `profile`, `email`) do not include `offline_access`, and Bifröst does not add it automatically.

##### Example with `offline_access` {: #device-auth-property-scopes-examples }
```yaml
scopes:
  - openid
  - email
  - profile
  - offline_access
```

<<property("retrieveIdToken", "bool", None, id_prefix="device-auth-", default=True, heading=4)>>
Will retrieve the ID Token and makes it available in the [corresponding context via `idToken`](../context/authorization.md#oidc-property-idToken).

If the identity provider does not return a new ID token during refresh, the previously verified token remains available only until it expires. Reconnecting with a `loginAllowed` rule that requires its claims may then fail even while the refresh grant remains valid; an expired ID token is never treated as fresh evidence.

<<property("retrieveUserInfo", "bool", None, id_prefix="device-auth-", default=False, heading=4)>>
Will retrieve the UserInfo and makes it available in the [corresponding context via `userInfo`](../context/authorization.md#oidc-property-userInfo).

<<property("forceDisposeSessionOn", "string", id_prefix="device-auth-", default="lostAccess", heading=4)>>
Controls forced session disposal when OIDC access can no longer be verified. Can be one of:

* `lostAccess`: Require a refresh token at login and check it while the session is active, even if `refreshToken.mode` is `never`. Dispose the session if its refresh token is missing or permanently rejected (for example, `invalid_grant`), or if no successful verification occurs within `refreshToken.maxUnverifiedFor` during an identity-provider outage. This is the default.
* `never`: Do not dispose a session because of a failed OIDC refresh. `refreshToken.mode: proactive` still requires a refresh token and refreshes it; set both properties to `never` to restore the previous behavior.

With `lostAccess`, a login without a refresh token is denied, and existing OIDC sessions without a refresh token or a recorded identity are disposed. If a refresh returns a new ID token, its issuer and subject must match the identity bound to the session. A refresh without a new ID token still checks that the provider accepts the refresh grant; it does not re-evaluate claims. This does not require UserInfo or periodically re-evaluate `loginAllowed`.

<<property("refreshToken", "Refresh Token", "#device-auth-refresh-token", id_prefix="device-auth-", heading=4)>>
Settings for refresh-token verification. Refresh is enabled when `forceDisposeSessionOn` is `lostAccess` or `refreshToken.mode` is `proactive`. When enabled, a login without a refresh token is denied.

### Refresh token {: #device-auth-refresh-token }

<<property("mode", "string", id_prefix="device-auth-refresh-token-", default="proactive", heading=4)>>
Can be one of:

* `proactive`: Refresh the token at the configured percentage of its lifetime. This does not force session disposal unless `forceDisposeSessionOn: lostAccess` is enabled. This is the default.
* `never`: Do not refresh tokens proactively unless `forceDisposeSessionOn: lostAccess` is enabled.

<<property("atLifetimePercent", "integer", id_prefix="device-auth-refresh-token-", default=70, heading=4)>>
Percentage of the token lifetime at which to refresh it, from `1` through `99`.

<<property("fallbackEvery", "Duration", "../data-type.md#duration", id_prefix="device-auth-refresh-token-", default="15m", heading=4)>>
Positive interval between refresh attempts when the token lifetime is unavailable.

<<property("maxUnverifiedFor", "Duration", "../data-type.md#duration", id_prefix="device-auth-refresh-token-", default="30m", heading=4)>>
Positive maximum time without successful refresh verification during transient identity-provider failures before `lostAccess` forces session disposal.

For `lostAccess`, a refresh is scheduled before this deadline if the configured access-token percentage would be later. A session that has already exceeded the deadline is disposed even if the identity provider becomes available again.

### Session cleanup

Before the session's retention period ends, a temporary ID-token verification or UserInfo failure leaves the stored authorization token in place for a later retry. After the session has expired **and** its configured retention period has elapsed, housekeeping removes the local OIDC token without contacting the identity provider again. It can then delete the session after successful environment disposal, subject to the configured [audit failure policy](../housekeeping.md#cleanup-guarantees). Bifröst does not revoke access or refresh tokens at the identity provider; OIDC disposal only removes the local token.

### Context {: #device-auth-context }

This authorization will produce a context of type [Authorization OIDC](../context/authorization.md#oidc).

### Examples {: #device-auth-examples }

1. Use the default `lostAccess` policy with a provider that requires `offline_access` to issue refresh tokens:
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
2. Retain the previous behavior temporarily while enabling refresh tokens at the identity provider:
   ```yaml
   type: oidcDeviceAuth
   issuer: https://login.microsoftonline.com/my-great-tenant-uuid/v2.0
   clientId: my-great-client-uuid
   clientSecret: very-secret-secret
   forceDisposeSessionOn: never
   refreshToken:
     mode: never
   ```

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
