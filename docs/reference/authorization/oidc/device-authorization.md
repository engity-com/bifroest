---
toc_depth: 4
description: Configure OIDC Device Authorization for SSH and browser access.
---

# OIDC Device Authorization

The SSH client or WebUI displays an IdP verification link and code. Users complete the login on the IdP's verification page.

Compared with [Authorization Code](authorization-code.md), the separate verification step can be less convenient. Not every IdP supports this grant; check the provider and client settings.

## Requirements

* Enable Device Authorization for the IdP client. A Device Authorization endpoint is required.
* Register a client ID and secret with the IdP.
* **SSH:** No Bifröst HTTP connection or callback URL is required.
* **WebUI:** Enable the [HTTP connection](../../connection/http/index.md) and choose **Interactive** to sign in.

Follow the IdP's verification instructions. Unlike Authorization Code, this flow has no separate Bifröst SSH approval page.

The WebUI shows this step in its login dialog and immediately tries to copy the code. Open the verification page with the button or **Enter**; if copying is blocked, enter the displayed code manually. Providers offering a complete verification URL do not require manual code entry. Ordinary keyboard-interactive prompts still use the authentication terminal.

## Properties

<<property("type", "Authorization Type", default="oidcDeviceAuth", required=True)>>
Set to `oidcDeviceAuth`.

<<property("rememberMe", "RememberMe", "../../data-type.md#rememberme", default="forbidden")>>
Controls saved browser and SSH access. Current session and refresh checks still apply.

<<property("issuer", "URL", "../../data-type.md#url", template_context="../../context/core.md", required=True)>>
Issuer URL supplied by the IdP, for example `https://idp.example.org/realms/company`.

The issuer and discovered device-authorization/token endpoints must use HTTPS. For a private CA, configure `SSL_CERT_FILE` in the Bifröst service environment.

<<property("clientId", "string", template_context="../../context/core.md", required=True)>>
Client ID registered at the IdP.

<<property("clientSecret", "string", template_context="../../context/core.md", required=True)>>
Secret for that client. Keep it in protected configuration, not source control.

| Token-endpoint method | Selection |
| --- | --- |
| `client_secret_basic` | Preferred; also used when metadata omits authentication methods |
| `client_secret_post` | Used when explicitly advertised and Basic is unavailable |

Cross-origin redirects from token and device-authorization endpoints are not followed.

<<property("scopes", array_ref("string"), template_context="../../context/core.md", default=["openid","profile","email"])>>
Scopes requested from the IdP.

Default refresh checks require a refresh token. Add your provider's required scope and client settings, often `offline_access`; Bifröst does not add it automatically.

<<property("ssh", "SSH", "#ssh")>>
Settings for [SSH clients](#ssh); ignored by the WebUI.

<<property("retrieveIdToken", "bool", default=True)>>
Exposes verified ID-token claims as [`.authorization.idToken`](../../context/authorization.md#oidc-property-idToken).

<<property("retrieveUserInfo", "bool", default=False)>>
Retrieves [`.authorization.userInfo`](../../context/authorization.md#oidc-property-userInfo). Its subject must match the authenticated identity.

<<property("forceDisposeSessionOn", "string", default="lostAccess")>>
Controls session disposal after OIDC access is lost.

| Value | Behavior |
| --- | --- |
| `lostAccess` | Requires a refresh token. Disposes the session when the grant is rejected or verification exceeds `maxUnverifiedFor`. |
| `never` | Does not dispose the session because of failed refresh checks. |

<<property("refreshToken", "Refresh Token", "#refresh-token")>>
Settings for [refresh checks](#refresh-token). A refresh token is required when either proactive refresh or `lostAccess` is enabled.

## SSH

<<property("loginMessage", "string", id_prefix="ssh-", default="")>>
Optional template for the SSH login instruction; ignored by the WebUI. An empty value uses the standard one-sentence instruction. `.url` is the verification URL, `.code` the device code and `.codeRequired` is `false` when the URL already includes verification information.

```yaml title="Example"
ssh:
  loginMessage: 'Sign in with code "{{ .code }}": {{ .url }}'
```

## Refresh token

<<property("mode", "string", id_prefix="refresh-token-", default="proactive")>>

| Value | Behavior |
| --- | --- |
| `proactive` | Refreshes the session's grant before access-token expiry. |
| `never` | Disables proactive refresh; `lostAccess` checks remain active. |

To disable refresh checks entirely, set both `forceDisposeSessionOn` and `refreshToken.mode` to `never`.

<<property("atLifetimePercent", "integer", id_prefix="refresh-token-", default=70)>>
Percentage of access-token lifetime at which to refresh, from `1` through `99`.

<<property("fallbackEvery", "Duration", "../../data-type.md#duration", id_prefix="refresh-token-", default="15m")>>
Positive interval between refresh attempts when token lifetime is unavailable.

<<property("maxUnverifiedFor", "Duration", "../../data-type.md#duration", id_prefix="refresh-token-", default="30m")>>
Maximum time without successful verification during an IdP outage. Must be positive. With `lostAccess`, exceeding this deadline disposes the session.

### Access and logout

* Refresh checks the grant, not necessarily current user/group claims or `loginAllowed`.
* Newly returned ID tokens must retain the session's issuer and subject. Unverifiable rotated credentials remain unusable until verified.
* Without a new ID token, existing claims are usable only until their token expires.
* Local session disposal does not revoke tokens at the IdP. User disablement is not guaranteed to invalidate existing refresh grants.

See [off-boarding deadlines](../../../usecases.md#offboard) for connection and session lifetime limits.

## Context

Provides an [Authorization OIDC](../../context/authorization.md#oidc) context.

## Examples

Use Device Authorization with the default refresh policy:

```yaml
type: oidcDeviceAuth
issuer: https://idp.example.org/realms/company
clientId: bifroest
clientSecret: YOUR_CLIENT_SECRET
scopes: [ openid, profile, offline_access ]
```

To permit saved browser and SSH access, add `rememberMe: allowed`. Current session and refresh checks still apply.

Changing an existing flow's grant requires a new login; it does not migrate saved access.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
