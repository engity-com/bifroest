---
description: Connect to Bifröst over SSH using OIDC Device Authorization and a browser, then open a Docker session.
---

# OIDC login with a standard SSH client

Bifröst can authorize an ordinary SSH login through your OpenID Connect (OIDC) provider. The user follows a **browser verification step**; no special SSH client is needed. This Linux example starts a separate Docker session instead of creating a host account.

You need a running [Bifröst host service](../setup/on-host.md), a reachable Docker daemon and an HTTPS OIDC issuer with **Device Authorization enabled**. Register a client that has a `clientId` and `clientSecret` and supports `client_secret_basic` or `client_secret_post` at the token endpoint. The provider must return a verifiable ID token with the client ID as audience. This flow is tested with a simulated IdP in the repository, **not with every external provider**.

## Configure the flow

Use the exact issuer URL and credentials from your IdP. Replace the host service's protected `/etc/engity/bifroest/configuration.yaml` with the following example; do not put its client secret in source control.

```yaml
ssh:
  handshakeTimeout: 5m
flows:
  - name: oidc-shell
    authorization:
      type: oidcDeviceAuth
      issuer: https://idp.example.org/realms/YOUR_REALM
      clientId: YOUR_CLIENT_ID
      clientSecret: YOUR_CLIENT_SECRET
      scopes: [openid]
    environment:
      type: docker
      image: alpine
      user: "1000:1000"
      portForwardingAllowed: false
      loginAllowed: '{{ eq .authorization.idToken.subject .remote.user }}'
```

The `loginAllowed` rule ties the requested SSH username to the verified ID token's **`sub` claim**. Find that user's `sub` at your IdP; it is usually not their email address. The container account `1000:1000` is independent of that identity. Protect the client secret, ensure the daemon can access Docker, and restart Bifröst:

```sh
sudo chmod 0600 /etc/engity/bifroest/configuration.yaml
sudo systemctl restart bifroest.service
```

## Log in

```sh
ssh YOUR_IDP_SUB@gateway.example.org 'id -u'
```

On the first login, open the URL shown by SSH in a browser, sign in at the **expected IdP**, enter the displayed code if prompted, and approve the request. The command should then print `1000` from the container. If the SSH client offered a public key, Bifröst can remember it for reconnects while the session remains valid; those reconnects may skip the browser step.

If login fails, check that Device Authorization is enabled for the client, the issuer and `sub` match, and the IdP permits the requested `openid` scope and client-secret method. For a private IdP CA, configure `SSL_CERT_FILE` in the Bifröst service environment; do not disable HTTPS verification. Docker socket access grants broad host privileges, and this example is not an isolation guarantee; see the [OIDC](../reference/authorization/oidc.md) and [Docker](../reference/environment/docker.md) references.

Disabling a user at the IdP blocks new authorizations according to the IdP's policy but does not automatically end an existing SSH connection. If you have a [time-bound off-boarding target](../usecases.md#offboard), also configure and test maximum connection and session lifetimes and account for any other access paths.
