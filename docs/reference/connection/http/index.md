---
description: Configure HTTPS access to browser terminals, management and SSH tunnels.
toc_depth: 5
---

# HTTP connection

Provides browser terminals, management and SSH tunnels over HTTP/TLS, plus a login page for [OIDC Authorization Code](../../authorization/oidc/authorization-code.md).

This connection type is optional and disabled by default; see [Browser access](../../../guides/browser-access.md) for a setup example.

Workload links use browser fragments, such as `/#Shell` or `/#alice@Shell`; see [access links and hidden Slugs](../../../guides/browser-access.md#access-links-and-hidden-slugs). Slugs are sent in API request bodies, never in API paths or query strings. Public discovery uses `POST /api/v1/discovery` with `{"slug":"Shell"}`. Only `/` serves the workspace document; workload and management targets remain in its fragment.

## Configuration

These properties belong to the root `http` block. `domains` and `tls` are required when HTTP is enabled.

<<property("enabled", "bool", default=False)>>
Enables HTTPS. There is no unencrypted HTTP fallback.

<<property("webUi", "WebUI", "#webui")>>
Controls the browser workspace and its API independently of SSH tunnels and the login page.

<<property("sshTunnel", "SSH tunnel", "#ssh-tunnel")>>
Controls SSH over HTTPS and WSS, without requiring a WebUI login or a direct SSH listener.

<<property("loginFlow", "Login flow", "#login-flow")>>
Controls the OIDC login page and its required endpoints independently of the workspace.

<<property("addresses", array_ref("Net Address", "../../data-type.md#net-address"), default=[":443"])>>
Addresses to listen on; at least one is required when enabled.

<<property("domains", array_ref("Host", "../../data-type.md#host"), required=True)>>
Accepted host names or IP addresses, without schemes, ports, paths or wildcards. Each needs a matching TLS certificate. [Flow requirements](../../flow.md#http-requirements) can restrict this list further.

<<property("tls", "TLS", "#tls", required=True)>>
Existing certificates, ACME, or self-signed TLS for local testing; see [TLS](#tls).

<<property("startupTimeout", "Duration", "../../data-type.md#duration", default="2m")>>
Maximum startup time, including certificate acquisition. Must be greater than zero.

<<property("readHeaderTimeout", "Duration", "../../data-type.md#duration", default="10s")>>
Timeout for reading request headers and initial request bodies. Must be greater than zero.

<<property("idleTimeout", "Duration", "../../data-type.md#duration", default="1m")>>
Idle HTTP keep-alive timeout, not the session lifetime or terminal [keepalive interval](../../flow.md#http-property-keepAlive). Must be greater than zero.

<<property("gracefulShutdownTimeout", "Duration", "../../data-type.md#duration", default="30s")>>
How long to wait for HTTP requests during shutdown. `0s` closes them immediately. SSH tunnels use the [SSH shutdown grace](../ssh.md#property-gracefulShutdownTimeout).

<<property("maxHeaderBytes", "uint32", default=1048576)>>
Maximum request-header size in bytes, from `1` to `16777216` (16 MiB).

<<property("rememberMe", "RememberMe", "#rememberme")>>
Controls how long an explicitly remembered browser can remain unused.

<<property("assetsDirectory", "File Path", "../../data-type.md#file-path", default="")>>
Override bundled browser files with local files. Missing files use the bundled version. Keep this directory separate from private service storage; changes to its root require a restart.

<<property("customCss", array_ref("File Path", "../../data-type.md#file-path"))>>
CSS files loaded after the built-in styles, in the listed order.

```yaml title="Example"
customCss: [custom/brand.css]
```

<<property("customJs", array_ref("File Path", "../../data-type.md#file-path"))>>
JavaScript files loaded after the built-in scripts, in the listed order. Only load trusted code: it has the same access as the application.

For example, set the workspace title before the application mounts:

```javascript title="custom/brand.js"
addEventListener('bifroest:configure', ({ detail }) => {
  detail.title = 'Operations';
});
```

<<property("customHtmlHead", "string", default="")>>
Trusted HTML appended to the document head, not a file path.

```yaml title="Example"
customHtmlHead: '<meta name="application-name" content="Operations">'
```

<<property("customHtmlBody", "string", default="")>>
Trusted HTML appended to the document body, not a file path.

## WebUI

These properties belong to `http.webUi`.

<<property("enabled", "bool", default=True, id_prefix="webui-", heading=3)>>
Enable the browser workspace and its API. Disabling it does not disable SSH tunnels or the OIDC login page.

## SSH tunnel

See [SSH over HTTPS with OpenSSH and curl](../../../guides/ssh-over-https.md) for client setup and connection examples.

These properties belong to `http.sshTunnel`.

<<property("enabled", "bool", default=True, id_prefix="ssh-tunnel-", heading=3)>>
Enable the SSH tunnel for native clients. Existing SSH authentication, host-key verification, [SSH flow requirements](../../flow.md), limits, auditing, SFTP and forwarding policies apply. Browser-only flows do not grant SSH access.

Transport admission additionally allows at most 1024 simultaneous tunnels, with at most 64 per direct peer IP. Lower SSH limits still apply; forwarded headers do not replace the peer address.

## Login flow

These properties belong to `http.loginFlow`.

<<property("enabled", "bool", default=True, id_prefix="login-flow-", heading=3)>>
Enable the login page, its resources and required OIDC endpoints, including when `http.webUi.enabled` is `false`. [OIDC Authorization Code](../../authorization/oidc/authorization-code.md) requires this component; configurations that disable it are rejected.

## TLS

TLS terminates directly at Bifröst; an HTTP reverse proxy must not terminate it instead. Existing certificates take priority over ACME.

### Configuration {: #tls-configuration }

These properties belong to `http.tls`.

<<property("dummy", "bool", default=False, id_prefix="tls-", heading=4)>>
Generate a temporary self-signed certificate for local testing. Cannot be combined with existing certificates or ACME.

!!! warning
    Use trusted certificates or ACME for production, not dummy TLS.

<<property("certificates", array_ref("Certificate", "#certificate"), id_prefix="tls-", heading=4)>>
PEM certificate/key pairs covering the configured domains.

<<property("acme", "ACME", "#acme", id_prefix="tls-", heading=4)>>
Optional automatic certificate issuance and renewal. Disabled by default.

### Certificate

Each entry in `http.tls.certificates` has these properties.

<<property("certificateFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Local PEM certificate-chain file.

<<property("privateKeyFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Local PEM private-key file, separate from SSH and audit keys. Do not put the key itself in the configuration.

### ACME

The configured DNS names must resolve to Bifröst, with public TCP port **443** reaching it directly. IP addresses and wildcard certificates are not supported by ACME.

#### Configuration {: #acme-configuration }

These properties belong to `http.tls.acme`.

<<property("enabled", "bool", default=False, id_prefix="acme-", heading=5)>>
Obtain and renew certificates for domains not covered by existing certificates.

<<property("acceptTerms", "bool", default=False, id_prefix="acme-", heading=5)>>
`true` means you accept the terms of the ACME directory, you defined via [`directoryUrl`](#acme-property-directoryUrl). In case of Let's Encrypt you can find them at https://letsencrypt.org/repository/. This is mandatory, when ACME is enabled.

<<property("email", "string", default="", id_prefix="acme-", heading=5)>>
Optional contact email address, without a display name.

<<property("directoryUrl", "URL", "../../data-type.md#url", default="https://acme-v02.api.letsencrypt.org/directory", id_prefix="acme-", heading=5)>>
Certificate authority's HTTPS directory. A staging service can be used for testing; its certificates are not browser-trusted.

<<property("storage", "File Path", "../../data-type.md#file-path", default="<os specific>", id_prefix="acme-", heading=5)>>
Persistent private directory for ACME account and certificate keys. Preserve it across restarts and keep it separate from public assets and other service storage.

###### Default settings

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| `/var/lib/engity/bifroest/http/acme` | `/Library/Application Support/Engity/Bifroest/http/acme` | `C:\ProgramData\Engity\Bifroest\http\acme` |

## RememberMe

The authorization's [RememberMe](../../data-type.md#rememberme) setting controls saved access. One non-exportable signing key is shared within this browser profile and origin; permissions remain separate. Resumption requires current authorization and a valid session. Use **Log out** to revoke saved access.

### Configuration {: #rememberme-configuration }

<<property("idleTimeout", "Duration", "../../data-type.md#duration", default="6h", id_prefix="rememberme-", heading=4)>>
Maximum inactivity of saved browser access; a successful resume resets it. Must be greater than zero. Shorter session limits still apply.

## Examples

Enable HTTPS with ACME for your existing flows:

```yaml
http:
  enabled: true
  domains: [bifroest.example.org]
  tls:
    acme:
      enabled: true
      acceptTerms: true
      email: operator@example.org
```

To expose only SSH over HTTPS/WSS, keep the HTTPS configuration above and set `ssh.enabled`, `http.webUi.enabled` and `http.loginFlow.enabled` to `false`. Leave `http.sshTunnel.enabled` at its default of `true`.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |

Browser access requires JavaScript, WebAssembly and WebCrypto; saved access also requires IndexedDB. Private-key import supports PEM/OpenSSH keys up to 64 KiB, not PPK, encrypted PKCS#8 or hardware keys. Native SSH tunnels do not require a browser.

SSH-key browser login also enforces the configured [SSH key restrictions](../ssh.md#keys), including the subject and CA keys of user certificates.

Browser artifact downloads are limited to 64 MiB per artifact; use the [CLI](../../cli/verification.md) for larger files. Browser terminals provide shells; use SSH for SFTP and port forwarding.

### curl transport capabilities

Use a current, security-maintained curl build with HTTPS support; WebSocket streaming also requires WSS support. Hover over or activate each asterisk for the expected version's test coverage.

| Transport | Minimum version |
| - | - |
| HTTPS streaming (HTTP/1.1) | <<minimum_version("8.15.0", "curl 8.18.0 on Linux (OpenSSL) and curl 8.22.0 on Windows (Schannel, via WSL interop). macOS has not been tested natively.")>> |
| WebSocket streaming (WSS) | <<minimum_version("8.16.0", "curl 8.18.0 on Linux (OpenSSL), including real SSH and simultaneous binary transfers. curl 8.22.0 on Windows (Schannel) failed concurrent duplex and is unsuitable for SSH over WSS. macOS has not been tested natively.")>> |
