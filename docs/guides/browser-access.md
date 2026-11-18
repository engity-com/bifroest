---
description: Enable HTTPS on a Linux Bifröst host and open a browser shell as an existing local account.
---

# Browser access

Open a shell on a Bifröst host with a browser instead of an SSH client. HTTPS access is optional and can run alongside SSH.

This Linux example requires the [extended release installed as a host service](../setup/on-host.md#linux), running as root, and an existing local account `alice` whose password is accepted by `/etc/pam.d/sshd`.

Point `bifroest.example.org` at the host and make TCP port 443 publicly reachable. Bifröst obtains and renews its certificate through ACME; TLS must terminate directly at Bifröst.

## Configure HTTPS and a terminal flow

Use the following configuration with your hostname, contact email and local account. Review the certificate authority's terms before setting `acceptTerms: true`. Keep another way to access the host while changing its service.

```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
http:
  enabled: true
  addresses: [":443"]
  domains: [bifroest.example.org]
  tls:
    acme:
      enabled: true
      acceptTerms: true
      email: operator@example.org

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
      rememberMe: allowedAndEnabledByDefault
      password:
        allowed: true
        emptyAllowed: false
    environment:
      type: local
      name: "{{.authorization.user.name}}"
      portForwardingAllowed: false
```

The flow authenticates `alice` and opens the shell as that verified local account. No account is created and no password belongs in the configuration.

!!! warning "Review every flow before enabling HTTPS"
    Enabling HTTP makes all flows HTTP-eligible by default. On an existing deployment, merge these settings and set `http: {enabled: false}` on each flow that must remain SSH-only.

Restart the service:

```sh
sudo systemctl restart bifroest.service
```

## Open your first shell

1. Open `https://bifroest.example.org/#Shell` and check the address and certificate.
2. Choose **Password**, enter `alice` and its password, then select **Sign in**. Leave **Remember this browser** unchecked for this first login.
3. In the new terminal, check the account and finish the shell:

    ```sh
    id -un
    exit
    ```

    `id -un` should print `alice`; a successful exit closes the terminal tab. If login fails, check the account's status and the host's PAM policy.

Reloading opens a new shell, not the old execution. Closing a tab is not logout; choose **Log out** to revoke browser access. The example enables [RememberMe](../reference/data-type.md#rememberme) by default; clear **Remember this browser** before login to opt out.

In terminals, use **Ctrl+Shift+C** to copy selected text and **Ctrl+Shift+V** to paste. **Ctrl+C** remains interrupt/cancel. Clipboard access may require browser permission.

## Access links and hidden Slugs

Use `https://bifroest.example.org/#alice@Shell` to prefill the user name. Editing the user name updates the link without reloading; email-style names are encoded, for example `#alice%40example.org@Shell`. User names in shared links are visible to their recipients and may be retained in browser history and bookmarks. They are hints, not verified identities.

Prefilled user names are also reflected in the link when a name-based login method is selected. After login, each tab and its copied access link retain that access's original requesting name, including after saved-login resumption. This name is separate from the identity verified by an external IdP. A missing required name is marked directly at its field.

The **Slug** field accepts free input as well as published suggestions. Enter a Slug and press **Enter**, or choose a suggestion. An unknown Slug is marked as invalid directly at the field; network and server errors remain separate and can be retried.

For a hidden link, omit `discoverAsSlug` and explicitly allow its Slug through `requirement.http.includedSlug`. A password manager can generate a long random alphanumeric Slug. Hidden Slugs are not listed to other visitors, but still require the flow's normal authentication and authorization.

Slugs and optional user names stay in the browser fragment, not document paths or request query strings. Discovery sends the Slug in a JSON body to `POST /api/v1/discovery`; other API calls also use request bodies, and WebSocket channels send it in their opening message. This keeps Slugs out of ordinary URL access logs, not out of explicitly configured body logging. Paths such as `/Shell` are not access links and return `404`.

## Next steps

* [Manage a host remotely](management.md) adds a management flow; terminal access alone grants no management access.
* [Record, find and replay a session](recording.md) enables optional output recording and verification.
* [HTTP configuration](../reference/connection/http/index.md) covers other deployment choices.
