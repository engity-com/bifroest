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

Reloading requires another sign-in and opens a new shell, not the old execution. Closing a tab is not logout; choose **Log out** to revoke its browser access. To enable saved access for this PAM flow, first review [`pamAccountResumeAllowed`](../reference/authorization/local.md#property-pamAccountResumeAllowed).

## Next steps

* [Manage a host remotely](management.md) adds a management flow; terminal access alone grants no management access.
* [Record, find and replay a session](recording.md) enables optional output recording and verification.
* [HTTP configuration](../reference/connection/http/index.md) covers other deployment choices.
