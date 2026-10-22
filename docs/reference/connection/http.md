---
description: HTTP endpoint configuration and validation groundwork for browser access.
toc_depth: 5
---
# HTTP / HTTPS

!!! warning "Configuration groundwork; no HTTP listener yet"
    This version parses and validates the settings below, but does not yet implement the HTTPS listener, certificate acquisition, asset serving, browser authentication or RememberMe. Setting `http.enabled: true` deliberately **fails the entire service startup**, before SSH listeners, keys, sessions or authorizers are prepared. It is not silently ignored. Keep HTTP omitted or disabled for an operational SSH-only deployment.

HTTP is a separate incoming transport for the same [flows](../flow.md), not SSH tunneled over WebSocket. Omission of the root `http` block means disabled. Merely configuring domains, TLS or customization does not enable it. When the endpoint is available, all flows are HTTP-eligible by default unless their individual `http.enabled` is false; `ssh.enabled` remains independent.

Configuration loading performs no certificate-file reads, key generation, ACME requests or asset-file reads. The schema supports explicit PEM certificate/key pairs, ACME, or both. A separate [TLS preparation core](#tls-preparation-core) now implements explicit certificate checks and an all-domain readiness barrier, but is **not yet integrated into service startup**. Actual ACME issuance/renewal and joint listener startup remain implementation work, not guarantees of successful schema validation.

## Properties

Under the root `http` mapping:

<<property("enabled", "bool", default=False)>>
:   Explicitly enables the startup-critical HTTPS input. There is no unencrypted HTTP fallback.

<<property("addresses", array_ref("Net Address", "../data-type.md#net-address"), default=[":443"])>>
:   TCP listener addresses. An enabled endpoint requires at least one. Empty entries and exact duplicates are rejected. The public TLS-ALPN-01 challenge port is 443; a different local port needs an external mapping to that port, not an HTTP reverse proxy terminating TLS elsewhere.

<<property("domains", array_ref("Host", "../data-type.md#host"))>>
:   A finite, explicit allowlist shared by certificate selection, host validation and discovery. Required when enabled. Wildcards, schemes, paths, ports and empty entries are rejected. DNS names normalize to lowercase IDNA ASCII without a trailing dot; IPv6 literals use brackets. Canonical duplicates are errors. Ports belong to `addresses`, not this list.

    Flow host requirements only narrow this list. An empty host matcher cannot authorize another domain or trigger certificate issuance for it. Published-slug collisions are checked against **every configured domain** when HTTP is enabled, both during configuration loading and service preparation; different non-overlapping domains may use the same slug. Disabled HTTP leaves legacy SSH flow selection unchanged.

<<property("tls", "TLS", "#tls")>>
:   Certificate sources. An enabled endpoint requires at least one configured certificate pair or explicitly enabled ACME.

<<property("startupTimeout", "Duration", "../data-type.md#duration", default="2m")>>
:   Positive budget reserved for joint HTTPS preparation, including initial certificate availability for all domains.

<<property("readHeaderTimeout", "Duration", "../data-type.md#duration", default="10s")>>
:   Positive HTTP request-header timeout.

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="1m")>>
:   Positive idle timeout for HTTP keep-alive connections. This is not a session or browser-RememberMe lifetime.

<<property("gracefulShutdownTimeout", "Duration", "../data-type.md#duration", default="30s")>>
:   Nonnegative HTTP shutdown grace period. Zero disables waiting for graceful completion.

<<property("maxHeaderBytes", "uint32", default=1048576)>>
:   Request-header size limit, from 1 through 16777216 bytes (16 MiB).

<<property("rememberMe", "RememberMe", "#rememberme")>>
:   Server-side browser binding settings, separate from imported private keys and SSH's existing key-based resumption.

<<property("assetsDirectory", "File Path", "../data-type.md#file-path", default="")>>
:   Optional complete asset-overlay directory. The planned contract is per-file filesystem-before-embedded lookup, including `index.html` and hashed bundles, never API or WebSocket routes. An empty value selects only embedded assets. Path containment, symlink checks and actual serving remain part of the asset implementation.

<<property("customCss", array_ref("File Path", "../data-type.md#file-path"))>>
:   Ordered local CSS files to append after built-in styles. These are file paths, not URLs or inline CSS.

<<property("customJs", array_ref("File Path", "../data-type.md#file-path"))>>
:   Ordered local JavaScript files to load after built-in resources. These are trusted same-origin operator code, not browser-supplied or remote URLs. Non-exportable browser keys do not protect against malicious same-origin code using those keys.

<<property("customHtmlHead", "string", default="")>>
:   Trusted operator HTML to append at the end of the document head, not a file path.

<<property("customHtmlBody", "string", default="")>>
:   Trusted operator HTML to append at the end of the document body, not a file path. Custom content does not permit iframe embedding or cross-origin API access.

Use real YAML booleans for flags and duration strings such as `30s`. Unknown fields, null values, quoted booleans and mismatched scalar/sequence/mapping types in the HTTP block are rejected, including values inherited through aliases and merge keys. Local paths follow the host operating system; Windows drive paths are accepted without being interpreted as URL schemes. Relative paths refer to the process working directory.

## TLS

Under `http.tls`:

<<property("certificates", array_ref("Certificate", "#certificate"), id_prefix="tls-", heading=3)>>
:   Ordered explicit certificate sources. The TLS preparation core prefers the first matching explicit certificate before consulting a certificate source for remaining allowed domains. A list can cover multiple domains; its actual certificate contents are not inspected by configuration validation.

<<property("acme", "ACME", "#acme", id_prefix="tls-", heading=3)>>
:   Optional automated certificate source. It remains disabled unless explicitly enabled, even if no explicit certificate is configured.

### Certificate

Each entry under `http.tls.certificates`:

<<property("certificateFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
:   Local PEM certificate chain file.

<<property("privateKeyFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
:   Local PEM private key file, **not inline private key material**. Configuration errors do not echo rejected key-field values.

### TLS preparation core

The server-side `pkg/https` package is tested independently of the service listener. It currently provides:

- Bounded certificate/key file reads, leaf/key matching, validity intervals, server-authentication usage, and signatures/order of supplied certificate-chain entries. Every configured pair must be valid and cover at least one allowed domain; a broken explicit pair does not silently fall back to ACME.
- Self-signed and private-CA certificates without requiring the server's OS public root store. The final supplied certificate is the explicit chain-validation anchor; a root need not be sent in a bundle. An omitted issuer cannot be verified locally. **Browser trust, missing-issuer resolution and revocation remain client checks**, not properties asserted by the server's preparation result.
- The existing private-file protection policy: Unix service ownership and no group/other access; on Windows a protected owner/SYSTEM access-control list. Explicit paths are resolved before loading. The loader does not repair permissions, generate missing keys or overwrite files. RSA keys require at least 2048 bits, ECDSA at least 256 bits; Ed25519 is also supported.
- SNI selection strictly limited to configured domains, even when a wildcard/SAN certificate covers more. Missing SNI is rejected for DNS names and ambiguous selections. Because browsers omit SNI for IP URLs, a sole explicitly configured IP literal can be selected without SNI; the future HTTP boundary must still enforce Host/SNI/Origin rules.
- An atomic initial readiness barrier: normal TLS handshakes fail until **all** configured domains have valid certificates. Before readiness, only an actively installed, domain-bound `acme-tls/1` proof is available. ClientHello requests never trigger certificate acquisition.
- Strict, temporary TLS-ALPN-01 proof validation: a single DNS name, the critical ACME SHA-256 identifier extension, self-signature and matching key. Cancellation/timeout/close invalidates proofs; releasing an older proof cannot remove a newer one. Proof certificates cannot become application certificates.
- Context-bound preparation and shutdown with no detached acquisition/renewal goroutines. TLS uses a minimum of TLS 1.2. Session tickets are initially disabled so resumption cannot bypass readiness or certificate-lifetime checks; supplied-chain expiration is rechecked for new handshakes.

Tests include actual TLS and TLS-ALPN proof handshakes, including private CA and IP cases. These tests do **not** contact an ACME CA or prove issuance, persistent account/certificate storage, renewal, browser authentication, or the joint SSH/HTTPS listener lifecycle. The service startup guard remains in place until that integration is complete.

### ACME

Under `http.tls.acme`:

<<property("enabled", "bool", default=False, id_prefix="acme-", heading=4)>>
:   Enables ACME for allowed domains not covered by explicit certificates. No on-demand issuance for arbitrary request hosts is permitted.

<<property("acceptTerms", "bool", default=False, id_prefix="acme-", heading=4)>>
:   Explicit consent to the chosen CA's terms. Must be true when ACME is enabled. Configuration parsing never accepts terms or contacts a CA itself.

<<property("email", "string", default="", id_prefix="acme-", heading=4)>>
:   Optional plain contact email address, without a display name.

<<property("directoryUrl", "string", default="https://acme-v02.api.letsencrypt.org/directory", id_prefix="acme-", heading=4)>>
:   Absolute HTTPS ACME directory URL, without embedded credentials, query or fragment. Use the CA's staging directory for issuance tests.

<<property("storage", "File Path", "../data-type.md#file-path", id_prefix="acme-", heading=4)>>
:   Persistent private ACME account/certificate storage, required when ACME is enabled. Defaults:

    - Linux/other Unix: `/var/lib/engity/bifroest/http/acme`
    - macOS: `/Library/Application Support/Engity/Bifroest/http/acme`
    - Windows: `C:\ProgramData\Engity\Bifroest\http\acme`

    This must not be an asset directory. Creation, restrictive permissions and renewal behavior belong to the pending TLS runtime implementation.

## RememberMe

Under `http.rememberMe`:

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="6h", id_prefix="rememberme-", heading=3)>>
:   Positive **sliding unused timeout** for explicitly opted-in browser bindings. Successful proof of possession extends it. Expiry requires regular login again; it does not terminate already authenticated connections, dispose sessions/containers, or override shorter session limits and revocations. This setting alone neither creates a binding nor implements browser RememberMe.

## Schema examples

These are complete, parser-checked configuration examples, **not yet runnable HTTPS deployments**. Both intentionally hit the startup guard while `enabled: true` remains set.

### Explicit certificates for internal domains

```yaml
http:
  enabled: true
  addresses: [":443"]
  domains: [app.internal.example, management.internal.example]
  tls:
    certificates:
      - certificateFile: certificates/internal-chain.pem
        privateKeyFile: certificates/internal-key.pem
  assetsDirectory: web-assets
  customCss: [custom/brand.css]
  customJs: [custom/brand.js]
  customHtmlHead: '<meta name="example" content="internal">'
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

### ACME with explicit consent and multiple domains

```yaml
http:
  enabled: true
  domains: [app.example.org, management.example.org]
  tls:
    acme:
      enabled: true
      acceptTerms: true
      email: operator@example.org
      directoryUrl: https://acme-staging-v02.api.letsencrypt.org/directory
  rememberMe:
    idleTimeout: 6h
flows:
  - name: management
    discoverAsSlug: management
    http:
      requestUser: false
    requirement:
      http:
        includedHost: '^management\.example\.org$'
    authorization:
      type: oidcDeviceAuth
      issuer: https://identity.example.org
      clientId: bifroest
      clientSecret: example-only
    environment:
      type: management
```

Browser authentication and the management UI will use the same authorization and management rights as SSH, not a second administrator login. An identity mapping for a local target must resolve to an allowed account; a name-free flow cannot synthesize an account from an untrusted slug.
