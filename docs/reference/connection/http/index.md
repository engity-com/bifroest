---
description: Configure HTTPS access to browser terminals, management and SSH tunnels.
toc_depth: 5
---

# HTTP connection

Provides browser terminals, management and SSH tunnels over HTTP/TLS, plus a login page for [OIDC Authorization Code](../../authorization/oidc/authorization-code.md).

This connection type is optional and disabled by default; see [Browser access](../../../guides/browser-access.md) for a setup example.

Workload links use browser fragments, such as `/#Shell` or `/#alice@Shell`; see [access links and hidden Slugs](../../../guides/browser-access.md#access-links-and-hidden-slugs). Paths such as `/Shell` are not access links.

## Configuration

These properties belong to the root `http` block. `domains` is required unless `enabled` is `false`.

<<property("enabled", "bool or string", default=False)>>
Selects what the listener serves:

| Value | Behavior |
| - | - |
| `false` | No HTTP listener |
| `true` | HTTP application endpoints, with TLS or trusted [reverse-proxy mode](#upstream) |
| `acmeTlsAlpnOnly` | Only [ACME TLS-ALPN-01 validation](../../transports/tls/index.md#acme); no WebUI, API, SSH tunnel or OIDC endpoints |

`acmeTlsAlpnOnly` requires [`tls`](#property-tls) with enabled ACME and uses `addresses` and `domains`. It cannot use reverse-proxy mode.

<<property("webUi", "WebUI", "#webui")>>
Controls the browser workspace and its API independently of SSH tunnels and the login page.

<<property("sshTunnel", "SSH tunnel", "#ssh-tunnel")>>
Controls SSH over HTTPS and WSS, without requiring a WebUI login or a direct SSH listener.

<<property("loginFlow", "Login flow", "#login-flow")>>
Controls the OIDC login page and its required endpoints independently of the workspace.

<<property("addresses", array_ref("Net Address", "../../data-type.md#net-address"), default=[":443"])>>
Addresses to listen on; at least one is required when enabled.

<<property("domains", array_ref("Host", "../../data-type.md#host"), required=True)>>
Accepted public host names or IP addresses, without schemes, ports, paths or wildcards. With backend TLS enabled, each needs a matching certificate. [Flow requirements](../../flow.md#http-requirements) can restrict this list further.

<<property("tls", "TLS or name", "../../transports/tls/index.md")>>
An inline [TLS definition](../../transports/tls/index.md) or the name of an entry in the root `tls` map. Omitted or `""` selects `tls.default` if defined; otherwise no TLS is configured. Set `tls: null` to disable TLS explicitly, including when a default exists. An unencrypted backend requires trusted [reverse-proxy mode](#upstream). `tls: {}` selects inline TLS with the default certificate files, not `tls.default`.

<<property("upstream", "Upstream", "#upstream")>>
Direct HTTPS or an explicitly trusted reverse proxy, including public path and port defaults.

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

Transport admission additionally allows at most 1024 simultaneous tunnels, with at most 64 per effective client IP. Lower SSH limits still apply. In direct mode this is the socket peer; reverse-proxy mode uses the [validated client chain](#upstream-forwarded-headers).

## Login flow

These properties belong to `http.loginFlow`.

<<property("enabled", "bool", default=True, id_prefix="login-flow-", heading=3)>>
Enable the login page, its resources and required OIDC endpoints, including when `http.webUi.enabled` is `false`. [OIDC Authorization Code](../../authorization/oidc/authorization-code.md) requires this component; configurations that disable it are rejected.

## Upstream

These properties belong to `http.upstream`.

<<property("mode", "string", default="direct", id_prefix="upstream-", heading=3)>>
`direct` uses Bifröst's TLS connection, SNI and Host; forwarded headers are ignored. `reverseProxy` requires a trusted socket peer and validated public HTTPS metadata on every request, including when backend TLS is enabled.

<<property("trustedPeers", array_ref("IP Address or Network", "../../data-type.md#ip-address-or-network"), id_prefix="upstream-", heading=3)>>
Required in proxy mode, with no default. List explicit proxy IPs or CIDRs. The optional value `private` includes RFC1918 IPv4 ranges and IPv6 ULA (`fc00::/7`), not loopback, link-local or CGNAT. It trusts all such private networks, not just your cluster; use narrow ranges and restrict backend access to your ingress.

<<property("defaultPrefix", "string", default="", id_prefix="upstream-", heading=3)>>
Public mount path for URLs generated without an HTTP request, notably SSH-initiated OIDC. Empty means root. Otherwise use an absolute path such as `/team/bifroest`, without a trailing slash. Segments may contain ASCII letters, digits and `-._~`, but not `.` or `..` alone. Encoded paths, empty segments, queries and fragments are rejected. Requires proxy mode when non-empty.

<<property("defaultPort", "uint16", default=0, id_prefix="upstream-", heading=3)>>
Public HTTPS port for URLs generated without an HTTP request. `0` selects the mode-specific default:

| Direct | Reverse proxy |
| - | - |
| First listener's port | `443` |

### Forwarded headers {: #upstream-forwarded-headers }

The ingress must remove client-supplied metadata and set the authoritative values below. RFC 7239 `Forwarded` is not used. Except for the comma-separated IP chain, duplicate headers and value lists are rejected.

| Header | Contract |
| - | - |
| `X-Forwarded-Proto` | Required, exactly `https`. Public HTTP is rejected. |
| `X-Forwarded-Host` | Optional single public authority, restricted by `http.domains`; otherwise the HTTP Host is used. Include a non-standard public port. |
| `X-Forwarded-Port` | Optional numeric port from `1` to `65535`; must agree with a port already present in the authority. |
| `X-Forwarded-For` | Required single IP chain. Evaluation starts at the socket peer and proceeds right to left while hops are trusted, stopping at the first untrusted address. The resulting IP is used for access rules, audit and client limits. |
| `X-Forwarded-Prefix` | Optional canonical mount path using the rules for `defaultPrefix`. Missing or empty means root, never the configured default. |

For subpaths, strip the public prefix and set `X-Forwarded-Prefix`; preserve Origin and browser fetch metadata. Restrict backend access to the ingress; internal HTTP is unencrypted. Subpaths do not isolate untrusted applications.

### Load balancers and instance routing

Keep browser access, pending logins and management confirmations on the instance that created them. For [SSH Authorization Code logins](../../authorization/oidc/authorization-code.md#login), SSH and HTTPS must reach the same instance; browser-cookie affinity alone is insufficient. After backend failure, users sign in again on a healthy instance. Sessions are not shared; see [HA deployment and recovery](../../../setup/operations.md#high-availability-current-limits).

## RememberMe

The authorization's [RememberMe](../../data-type.md#rememberme) setting controls saved access. One non-exportable signing key is shared within this browser profile, origin and mount path; permissions remain separate. Resumption requires current authorization and a valid session. Use **Log out** to revoke saved access.

### Configuration {: #rememberme-configuration }

<<property("idleTimeout", "Duration", "../../data-type.md#duration", default="6h", id_prefix="rememberme-", heading=4)>>
Maximum inactivity of saved browser access; a successful resume resets it. Must be greater than zero. Shorter session limits still apply.

## Examples

Add one of these configurations to your existing flows.

### HTTPS with ACME

Serve browser access, SSH tunnels and OIDC login endpoints over HTTPS:

```yaml
http:
  enabled: true
  domains: [bifroest.example.org]
  tls:
    acme:
      acceptTerms: true
      email: operator@example.org
```

### SSH tunnels only

Keep SSH over HTTPS/WSS, without a direct SSH listener, WebUI or OIDC login page:

```yaml
ssh:
  enabled: false
http:
  enabled: true
  domains: [bifroest.example.org]
  tls:
    acme:
      acceptTerms: true
      email: operator@example.org
  webUi:
    enabled: false
  loginFlow:
    enabled: false
```

Connect using [OpenSSH and curl](../../../guides/ssh-over-https.md).

### Behind a reverse proxy

For a TLS-terminating ingress at `https://gateway.example.org/bifroest/`, forwarding from `10.20.0.0/24` to backend port `8080`:

```yaml
http:
  enabled: true
  addresses: [":8080"]
  domains: [gateway.example.org]
  tls: null
  upstream:
    mode: reverseProxy
    trustedPeers: [10.20.0.0/24]
    defaultPrefix: /bifroest
```

The backend connection is unencrypted. Restrict that port to the ingress and apply the [header and rewrite contract](#upstream-forwarded-headers). Set `defaultPort` as well if the public HTTPS port is not `443`.

For Kubernetes, see [HTTP ingress with Helm](../../../setup/in-kubernetes.md#http-ingress).

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
