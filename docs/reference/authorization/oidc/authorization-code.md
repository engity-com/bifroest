---
toc_depth: 4
description: Configure OIDC Authorization Code with PKCE for SSH and browser access.
---

# OIDC Authorization Code

Authenticates through an IdP browser redirect with PKCE S256. Compared with [Device Authorization](device-authorization.md), this often provides simpler SSO and broader IdP compatibility. PKCE and browser binding can offer security advantages, depending on the setup.

## Requirements

* Enable the [HTTP connection](../../connection/http/index.md), including for SSH logins.
* Register a confidential web client at the IdP with Authorization Code and PKCE S256 enabled.
* Register `https://<domain>/login/callback` as the exact callback URL; see [`domain`](#property-domain).

!!! note "Browser sign-in for SSH"
    You can use the browser just to confirm an SSH login, without offering access through the WebUI. Users confirm their login in the browser, then return to their SSH client to work.

## Login

* **SSH:** Open your own login link; it redirects to the IdP automatically. After signing in, select your SSH client's two-character code from three choices, or decline. A wrong choice or decline aborts the login.
* **WebUI:** Choose **OIDC**. Login opens in a separate tab, without code selection; use the fallback link if popups are blocked. The tab closes automatically when possible, keeping the original application and its sessions intact.

Never approve someone else's SSH login link. Pending browser logins are memory-only; a Bifröst restart or loss of the initiating WebUI tab requires a new login.

Browser success means the original login passed Bifröst's access, session and required audit checks, not just the IdP login. Code selection is an active confirmation, not MFA: guessing succeeds with probability 1/3 and it cannot prevent deliberate phishing. Configure MFA or passkeys at the IdP.

## Properties

<<property("type", "Authorization Type", default="oidcAuthorizationCode", required=True)>>
Set to `oidcAuthorizationCode`.

<<property("ssh", "SSH", "#ssh")>>
Settings for [SSH clients](#ssh); ignored by the WebUI.

<<property("rememberMe", "RememberMe", "../../data-type.md#rememberme", default="forbidden")>>
Controls saved browser and SSH access. Current session and refresh checks still apply.

<<property("issuer", "URL", "../../data-type.md#url", template_context="../../context/core.md", required=True)>>
Issuer URL supplied by the IdP, for example `https://idp.example.org/realms/company`.

The issuer and discovered authorization/token endpoints must use HTTPS. For a private CA, configure `SSL_CERT_FILE` in the Bifröst service environment.

<<property("clientId", "string", template_context="../../context/core.md", required=True)>>
Client ID registered at the IdP.

<<property("clientSecret", "string", template_context="../../context/core.md", required=True)>>
Secret for that client. Keep it in protected configuration, not source control.

| Token-endpoint method | Selection |
| --- | --- |
| `client_secret_basic` | Preferred; also used when metadata omits authentication methods |
| `client_secret_post` | Used when explicitly advertised and Basic is unavailable |

Cross-origin redirects from the token endpoint are not followed.

<<property("scopes", array_ref("string"), template_context="../../context/core.md", default=["openid","profile","email"])>>
Scopes requested from the IdP. Must include `openid`.

Default refresh checks require a refresh token. Add your provider's required scope and client settings, often `offline_access`; Bifröst does not add it automatically.

<<property("domain", "Host", "../../data-type.md#host", default="<first http.domains entry>")>>
Selects one of the configured [`http.domains`](../../connection/http/index.md#property-domains). Omit the scheme, port and path.

The callback is `https://<domain>/login/callback`. A non-standard port comes from the first HTTP listener. Register this exact URL at the IdP; an ephemeral listener port (`:0`) is not supported.

<<property("loginTimeout", "Duration", "../../data-type.md#duration", default="2m")>>
Maximum time for the login, including browser approval. Must be greater than zero and at most `10m`. SSH also applies its remaining [`handshakeTimeout`](../../connection/ssh.md#property-handshakeTimeout).

The same deadline covers final target validation and required audit recording. A delayed WebUI claim or audit completion cannot grant access after expiration.

<<property("retrieveIdToken", "bool", default=True)>>
Exposes verified ID-token claims as [`.authorization.idToken`](../../context/authorization.md#oidc-property-idToken).

The ID token is always verified, even when this setting is `false`.

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
Optional template for the SSH login instruction; ignored by the WebUI. An empty value uses the standard one-sentence instruction. `.url` is the Bifröst login link, `.code` the two-character comparison code and `.codeRequired` is `true`.

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

Use the default refresh policy and select a configured HTTP domain:

```yaml
type: oidcAuthorizationCode
issuer: https://idp.example.org/realms/company
clientId: bifroest
clientSecret: YOUR_CLIENT_SECRET
scopes: [ openid, profile, offline_access ]
domain: gateway.example.org
loginTimeout: 2m
```

For a complete SSH and WebUI configuration, see the [OIDC login guide](../../../guides/oidc.md#configuration).

Changing an existing flow's grant requires a new login; it does not migrate saved access.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
