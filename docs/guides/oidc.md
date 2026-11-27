---
description: Set up OIDC login for SSH and the WebUI with Authorization Code and PKCE.
---

# OIDC login

Sign in through your identity provider, then open a session with a normal SSH client or the WebUI. This example uses Authorization Code with PKCE and runs the session in Docker.

## Prerequisites

* A Linux [Bifröst host service](../setup/on-host.md) with access to Docker.
* A domain pointing to Bifröst, with TCP port 443 reachable.
* An OIDC provider and the `sub` claim of the user you want to allow.

## 1. Register the IdP client {: #idp-client }

Use these settings, substituting your own domain:

| Setting | Value |
| --- | --- |
| Client type | Confidential web client with a client ID and secret |
| Grant | Authorization Code with PKCE S256 |
| Callback URL | `https://gateway.example.org/login/callback` |
| Token authentication | `client_secret_basic` or `client_secret_post` |
| Tokens | ID token and refresh token |

Enable your provider's refresh-token scope/settings. The example uses `offline_access`.

## 2. Configure Bifröst {: #configuration }

Merge this into your host configuration. Replace the domain, ACME contact, issuer, credentials and allowed subject.

```yaml title="/etc/engity/bifroest/configuration.yaml"
tls:
  default:
    acme:
      # Set this to true means you accept the terms of:
      # https://letsencrypt.org/repository/
      acceptTerms: true
      email: operator@example.org
http:
  enabled: true
  domains: [ gateway.example.org ]
  ## The "default" TLS config is used implicitly.
  # tls: default

flows:
  - name: oidc-shell
    discoverAsSlug: Shell
    http:
      requestUser: false
    requirement:
      http:
        includedSlug: '^Shell$'
    authorization:
      type: oidcAuthorizationCode
      issuer: https://idp.example.org/realms/company
      clientId: YOUR_CLIENT_ID
      clientSecret: YOUR_CLIENT_SECRET
      scopes: [ openid, profile, offline_access ]
    environment:
      type: docker
      image: alpine
      user: "1000:1000"

      # Allows users with the field `shell` is equal to `true`
      # in their ID Token returned by the IdP to login.
      loginAllowed: '{{ eq .authorization.idToken.shell "true" }}'
```

(Re)start your Bifröst instance to active this configuration.

## 3. Sign in {: #sign-in }

### Via SSH {: #sign-in-via-ssh }

```sh
ssh gateway.example.org 'id -u'
```

1. Open the login link shown by your SSH client.
2. Sign in at your IdP.
3. Select your SSH client's two-character code from the browser's three choices to approve **your own** connection. A wrong choice or decline aborts the login.

The command should print `1000`. Never approve a login link sent by someone else.

### Via WebUI {: #sign-in-via-webui }

1. Open `https://gateway.example.org/#Shell` and choose **OIDC**.
2. Sign in at your IdP in the automatically opened tab. If popups are blocked, use the displayed login link.
3. The login tab closes automatically when possible. Return to the original tab to use the terminal; WebUI login has no SSH code selection.

Keep the original tab open; reloading it loses the pending login.

## Alternatives

| Need | Change |
| --- | --- |
| SSH only, with browser approval | Keep global HTTPS enabled; set the flow's `http.enabled` to `false`. `/` then returns `404` if no HTTP-enabled flow remains. |
| SSH without Bifröst HTTPS | Enable Device Authorization at the IdP and use `type: oidcDeviceAuth`. Follow the IdP's verification instructions instead of the Bifröst approval step. |
| Saved access | Configure [`rememberMe`](../reference/authorization/oidc/authorization-code.md#property-rememberMe). Session and refresh checks still apply. |

## Troubleshooting

| Problem | Check |
| --- | --- |
| Callback fails | Registered callback URL, selected HTTP domain, port and TLS certificate |
| No refresh token | IdP client settings and required scopes |
| IdP login succeeds, access denied | Allowed `sub` and the environment's `loginAllowed` rule |

## Next steps

* [Authorization Code reference](../reference/authorization/oidc/authorization-code.md#refresh-token) covers refresh checks and access-loss behavior.
* [Docker reference](../reference/environment/docker.md) explains workload privileges and isolation.
* [Device Authorization reference](../reference/authorization/oidc/device-authorization.md) covers the alternative flow without a Bifröst HTTP connection for SSH.
