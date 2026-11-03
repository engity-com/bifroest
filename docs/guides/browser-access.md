---
description: Enable HTTPS on a Linux Bifröst host and open a browser shell as an existing local account.
---

# Browser access

This Linux example opens a shell in your browser without an SSH client or tunnel. HTTPS is optional; SSH access can remain available separately.

## Before you start

* Install the [Linux extended release as a host service](../setup/on-host.md#linux). Local authorization and starting another user's shell require root privileges. Use a release build with the browser UI and documentation from the same release; a source-only Go build may not include it.
* Have an existing local account, `alice` below, with a nonempty password accepted by your host's `sshd` PAM authentication and account policy. This example creates no account and grants no additional account permissions.
* Point `bifroest.example.org` at the host, with TCP port 443 reachable. Have a browser-trusted PEM certificate chain for that name and a separate private-key file readable by Bifröst. Protect the private key and do not reuse an SSH or audit key.

Bifröst must terminate TLS directly. Open the configured HTTPS address, not an IP alias or a TLS-terminating HTTP reverse proxy. Browser requests must stay on that HTTPS origin, including its port. See [Security and limits](../reference/connection/http/security.md) for deployment boundaries.

## Configure HTTPS and a terminal flow

For the fresh host installation, use this configuration in `/etc/engity/bifroest/configuration.yaml`. Replace the hostname, certificate paths and `alice` with your actual values. Keep another way to access the host while changing its service.

```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
http:
  enabled: true
  addresses: [":443"]
  domains: [bifroest.example.org]
  tls:
    certificates:
      - certificateFile: /etc/engity/bifroest/https/fullchain.pem
        privateKeyFile: /etc/engity/bifroest/https/private-key.pem

flows:
  - name: local
    discoverAsSlug: Shell
    http:
      requestUser: true
    requirement:
      includedRequestingName: ^alice$
      http:
        includedSlug: '^Shell$'
    authorization:
      type: local
      password:
        allowed: true
        emptyAllowed: false
    environment:
      type: local
      name: "{{.authorization.user.name}}"
      portForwardingAllowed: false
```

The requested name must be `alice`; local authorization checks that account. The environment uses the **verified local account name**, not a name taken from the URL. The extended Linux build uses the `sshd` PAM service by default. No user password belongs in this configuration.

!!! warning "Review every flow before enabling HTTPS"
    With root `http.enabled: true`, all flows are HTTP-eligible by default. On an existing deployment, merge these settings and set `http: {enabled: false}` on each flow that must remain SSH-only. Publishing a link does not grant access. This example also restricts SSH login to `alice` through the same flow.

Restart the service after provisioning the certificate files:

```shell
sudo systemctl restart bifroest.service
```

Configured SSH and HTTPS listeners must both start successfully. If startup fails, check the certificate name, paths, permissions and service log; Bifröst does not silently fall back to SSH-only operation.

## Open your first shell

1. Open `https://bifroest.example.org/Shell` and check the address and certificate.
2. Select **Password**. Enter `alice` in **User name** and the account password in **Password**. The user name is required; the published link does not supply it.
3. Leave **Remember this browser** unchecked for this first login and select **Sign in**. A successful login opens a terminal tab.
4. In that terminal, check the account and finish the shell:

    ```shell
    id -un
    exit
    ```

    `id -un` should print `alice`. If login is refused, check the existing account's status and `/etc/pam.d/sshd`; see [local password authorization](../reference/authorization/local.md#password).

Other flows can offer **Interactive** for keyboard-interactive/OIDC device login or **SSH key** for locally signed key login. Only potentially supported methods appear; dynamic rules and credentials are checked at login. Choose another **Slug** to update the URL and its sign-in options. Existing connection tabs stay unchanged.

Opening `/` selects `/Shell` automatically if it is the only available link,
without signing in or resuming saved access. No Slug dropdown is shown unless
another access scope is available. With several links, `/` instead offers the
selection; this directory-only root is not a selectable login Slug. The
published link must match the flow's slug requirements; a contradiction prevents
startup. Without slug rules, a flow accepts only `/`.

## Returning and leaving

Reloading does not restore a running shell. Sign in again, or explicitly select **Use saved access**, to open a new shell. Compatible SSH and browser logins can reuse the same session and workspace, not the previous execution.

Selecting an existing tab changes the URL to the access scope that tab originally
used, including an alias rather than its published link. This does not sign in
again, change its session or workload, reconnect, or fetch discovery again.
Browser Back/Forward keeps the displayed scope and URL consistent; it does not
replay authentication or execution. Resolve an unfinished login or critical
action before changing Slug.

**Remember this browser** is a separate opt-in, not automatic login. It saves independent browser credentials, not your password or imported SSH key. Eligibility depends on the authorization method and platform. In this PAM-backed example it requires an operator-reviewed server opt-in; see [local RememberMe](../reference/authorization/local.md#browser-rememberme) before enabling it.

* Confirming closure of a live terminal tab closes that connection, not other tabs or the session. Closing the page is not logout either.
* **Log out** closes connections owned by that browser access and revokes its linked saved access, if present. It does not disconnect unrelated SSH access or dispose of the workspace.
* **Dispose session** is a separate management action. It revokes the session and runs its configured cleanup, which can remove workloads or managed accounts.

The terminal's **Connection settings** can change its keepalive interval unless the flow enforces one. Keepalive does not extend session or login lifetimes; see [flow keepalive](../reference/flow.md#http-property-keepAlive).

## Next steps

* [Manage a host remotely](management.md) adds a management flow; terminal access alone grants no management access.
* [Record, find and replay a session](recording.md) enables optional output recording and verification.
* [HTTP configuration](../reference/connection/http/index.md) and [Security and limits](../reference/connection/http/security.md) cover other deployment choices and browser limits.
