---
description: Configure HTTPS access to browser terminals and management.
toc_depth: 5
---

# HTTP connection

Connect to Bifröst with a browser over HTTPS. The browser provides terminal tabs,
session management and local recording verification and playback.

HTTP and [SSH](ssh.md) use the same [flows](../flow.md), authorizations, sessions
and environments. HTTP is optional and disabled by default. Enabling it does not
disable SSH or grant additional management rights.

Follow the [browser access guide](../../guides/browser-access.md) to open a first
terminal. See [Security and limits](http/security.md) for saved-access behavior,
management permissions and browser limits.

!!! note
    Bifröst must terminate TLS itself. A TCP pass-through proxy is possible;
    TLS termination at an HTTP reverse proxy is not supported. If a configured
    listener or certificate fails during startup, the service does not start
    with only the remaining transport.

## Configuration

These properties belong to the root `http` block.
`domains` and `tls` are required when HTTP is enabled.

<<property("enabled", "bool", default=False)>>
Enables HTTPS. There is no unencrypted HTTP fallback.

<<property("addresses", array_ref("Net Address", "../data-type.md#net-address"), default=[":443"])>>
TCP addresses to listen on. At least one is required when HTTP is enabled.

<<property("domains", array_ref("Host", "../data-type.md#host"), required=True)>>
Host names or IP addresses accepted by this endpoint. Do not include schemes,
ports, paths or wildcards. Every configured domain needs a valid certificate.

Flow [host requirements](../flow.md#http-requirements) can restrict this list
further, but cannot add domains.

<<property("tls", "TLS", "#tls", required=True)>>
Certificate sources. Configure certificates, enable ACME, or explicitly select
dummy TLS for local testing.

<<property("startupTimeout", "Duration", "../data-type.md#duration", default="2m")>>
Maximum time to prepare HTTPS, including initial certificate acquisition. Must
be greater than zero.

<<property("readHeaderTimeout", "Duration", "../data-type.md#duration", default="10s")>>
Timeout for reading request headers. Also limits initial request-body reads.
Must be greater than zero.

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="1m")>>
Idle timeout for HTTP keep-alive connections. Must be greater than zero. This is
not the session lifetime or the terminal's [keepalive interval](../flow.md#http-property-keepAlive).

<<property("gracefulShutdownTimeout", "Duration", "../data-type.md#duration", default="30s")>>
How long to wait for HTTP requests during shutdown. `0` closes them immediately.

<<property("maxHeaderBytes", "uint32", default=1048576)>>
Maximum request-header size in bytes. Must be between `1` and `16777216` (16 MiB).

<<property("rememberMe", "RememberMe", "#rememberme")>>
Controls how long an explicitly remembered browser can remain unused.

<<property("assetsDirectory", "File Path", "../data-type.md#file-path", default="")>>
Optional directory overriding embedded browser files, one file at a time.
Missing files use the embedded version. An unreadable or unsafe file is rejected
instead. Leave empty to use only the bundled application.

The directory cannot overlap session, audit, recording or private-key storage.
Replacing its root directory requires a restart.

<<property("customCss", array_ref("File Path", "../data-type.md#file-path"))>>
Local CSS files loaded after the built-in styles, in the listed order.

```yaml title="Example"
customCss: [custom/brand.css]
```

<<property("customJs", array_ref("File Path", "../data-type.md#file-path"))>>
Local JavaScript files loaded after the built-in scripts, in the listed order.
These scripts have the same trust as the browser application. Only load code
you trust with authenticated access and browser-held keys.

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
Trusted HTML appended to the document body, not a file path. Customization does
not enable iframe embedding or cross-origin API access.

Paths are local to the server. Relative paths use its working directory. Custom
files must be separate from private service state; symlinks are not supported.

## TLS

Use an existing certificate, ACME, or dummy TLS. Existing certificates take
priority; ACME can cover the remaining domains. Certificates and keys must be
valid and readable by the service. Browser trust is checked separately by the
browser.

TLS private keys must be separate from SSH and audit keys. Protect their file
permissions; Bifröst does not repair them or replace broken certificate files.

### Configuration {: #tls-configuration }

These properties belong to `http.tls`.

<<property("dummy", "bool", default=False, id_prefix="tls-", heading=4)>>
Generates a temporary self-signed certificate for local testing. It expires
after 24 hours and is replaced on restart. Cannot be combined with certificates
or enabled ACME.

!!! warning
    Dummy TLS is not browser-trusted. Do not use it with production credentials
    or install its certificate as a trusted CA. Use an existing trusted
    certificate or ACME for normal operation.

<<property("certificates", array_ref("Certificate", "#certificate"), id_prefix="tls-", heading=4)>>
PEM certificate/key pairs. The first matching certificate is used. Each pair
must cover at least one configured domain.

<<property("acme", "ACME", "#acme", id_prefix="tls-", heading=4)>>
Optional automatic certificate issuance and renewal. Disabled by default.

### Certificate

Each entry in `http.tls.certificates` has these properties.

<<property("certificateFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Local PEM certificate-chain file.

<<property("privateKeyFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
Local PEM private-key file. Do not put the key itself in the configuration.

### ACME

ACME uses TLS-ALPN-01. The configured DNS names must resolve to this service,
and public TCP port **443** must reach Bifröst, even if its local listener uses
another port. IP addresses require an existing certificate. HTTP-01, DNS-01 and
wildcard issuance are not supported.

Valid cached certificates allow startup when the CA is unavailable. Renewal
failure retains the current certificate, but does not allow serving it past
expiry. Preserve ACME storage across restarts.

#### Configuration {: #acme-configuration }

These properties belong to `http.tls.acme`.

<<property("enabled", "bool", default=False, id_prefix="acme-", heading=5)>>
Enables ACME for configured domains not covered by existing certificates.

<<property("acceptTerms", "bool", default=False, id_prefix="acme-", heading=5)>>
Accepts the selected CA's terms. Must be `true` when ACME is enabled.

<<property("email", "string", default="", id_prefix="acme-", heading=5)>>
Optional contact email address, without a display name.

<<property("directoryUrl", "string", default="https://acme-v02.api.letsencrypt.org/directory", id_prefix="acme-", heading=5)>>
HTTPS directory URL of the CA. Use its staging service when testing issuance.
Staging certificates are not trusted by normal browsers.

<<property("storage", "File Path", "../data-type.md#file-path", id_prefix="acme-", heading=5)>>
Private persistent directory for ACME account and certificate keys. Defaults:

* Linux: `/var/lib/engity/bifroest/http/acme`
* macOS: `/Library/Application Support/Engity/Bifroest/http/acme`
* Windows: `C:\ProgramData\Engity\Bifroest\http\acme`

Keep it separate from public assets, session storage and audit/recording data.

## RememberMe

RememberMe requires explicit opt-in during login. It stores independent browser
keys, not the login password or imported SSH private key. Saved access still
requires current authorization and a valid session. See the authorizer's
[supported methods](../authorization/index.md).

Closing a tab is not logout. Explicit logout revokes that browser access and its
linked connections; it does not dispose the shared session or workload.

### Configuration {: #rememberme-configuration }

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="6h", id_prefix="rememberme-", heading=4)>>
How long a remembered browser may remain unused. A successful resume starts a
new inactivity period. Must be greater than zero. Shorter session lifetimes and
revocation still apply. Expiry does not close an already authenticated terminal.

## Examples

These are complete configurations. Use your own domains, credentials and
allowed target accounts. Certificate files and custom files must exist before
startup.

### Local testing

This example binds only to loopback and opens the Dummy environment. The browser
will warn about the self-signed certificate. It grants unauthenticated test
access; do not expose these listeners publicly.

```yaml
ssh:
  addresses: ["127.0.0.1:2222"]
http:
  enabled: true
  addresses: ["127.0.0.1:8443"]
  domains: [localhost, 127.0.0.1]
  tls:
    dummy: true
flows:
  - name: local-test
    authorization:
      type: none
    environment:
      type: dummy
```

### Existing certificates

This example requires a certificate covering both domains. The verified OIDC
principal must map to an allowed local account.

```yaml
http:
  enabled: true
  addresses: [":443"]
  domains: [app.internal.example, management.internal.example]
  tls:
    certificates:
      - certificateFile: certificates/internal-chain.pem
        privateKeyFile: certificates/internal-key.pem
  customCss: [custom/brand.css]
flows:
  - name: work
    discoverAsSlug: work
    authorization:
      type: oidcDeviceAuth
      issuer: https://identity.example.org
      clientId: bifroest
      clientSecret: example-only
    environment:
      type: local
      name: '{{ .authentication.principal }}'
```

### ACME and browser management

This example uses Let's Encrypt's production service and publishes
`https://management.example.org/management`. Review its terms before setting
`acceptTerms: true`. The identity provider must permit device authorization.

```yaml
http:
  enabled: true
  domains: [management.example.org]
  tls:
    acme:
      enabled: true
      acceptTerms: true
      email: operator@example.org
  rememberMe:
    idleTimeout: 6h
flows:
  - name: management
    discoverAsSlug: management
    http:
      requestUser: false
    authorization:
      type: oidcDeviceAuth
      issuer: https://identity.example.org
      clientId: bifroest
      clientSecret: example-only
    environment:
      type: management
```

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |

The browser requires JavaScript, WebAssembly and WebCrypto in a secure context.
RememberMe additionally requires IndexedDB. Private-key import supports PEM and
OpenSSH keys, not PPK, encrypted PKCS#8 or hardware/security keys.

Browser terminals support shells, not SFTP or port forwarding. Use SSH for those
operations. Each new connection starts a fresh execution; reload does not
reattach to an earlier terminal.
