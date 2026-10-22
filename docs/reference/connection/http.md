---
description: HTTPS listener, certificate and browser transport configuration.
toc_depth: 5
---
# HTTP / HTTPS

!!! warning "Password API and discovery; no interactive browser workspace yet"
    Enabled HTTPS now serves published access links, flow-selection metadata and a password login API using the same authorizer/session selector as SSH. Keyboard-interactive/OIDC browser login, public-key browser challenges, RememberMe, React frontend, assets, WebSocket terminals and browser Management actions remain unimplemented. The previous blanket 501 response is replaced by these initial routes; unknown internal routes still return 404. Keep HTTP omitted or disabled unless you intend to expose this partial API.

HTTP is a separate incoming transport for the same [flows](../flow.md), not SSH tunneled over WebSocket. Omission of the root `http` block means disabled. Merely configuring domains, TLS or customization does not enable it. When the endpoint is available, all flows are HTTP-eligible by default unless their individual `http.enabled` is false; `ssh.enabled` remains independent.

Configuration loading performs no certificate-file reads, key generation, ACME requests or asset-file reads. The schema supports explicit PEM certificate/key pairs, ACME, or both. The [TLS preparation core](#tls-preparation-core) and [ACME backend](#acme-backend-and-renewal) are integrated into the [joint listener lifecycle](#joint-listener-lifecycle). Schema validation alone does not prove certificate availability or port binding.

## Joint listener lifecycle

All configured SSH and HTTPS TCP inputs are bound before any challenge or application transport is served. A binding failure closes every previously bound input without starting ACME acquisition. Service preparation can already have created SSH keys and other persistent service resources; failure does not delete that state.

The HTTPS listeners then serve only active TLS-ALPN-01 proofs while initial certificate preparation runs. Normal TLS handshakes and SSH serving remain blocked until **every configured domain** has valid material. A failed domain, acquisition timeout, cancellation or unexpected listener exit cancels preparation, removes proofs and closes all inputs. Successfully persisted certificates remain available for the next start.

After readiness, SSH and HTTPS run together, with a caller-owned ACME renewal loop. Unexpected termination of **either** transport stops the whole service; a half-running deployment is not considered successful. Shutdown stops accepting, cancels acquisition/renewal, drains HTTP for at most `gracefulShutdownTimeout` and then closes remaining HTTP connections. SSH retains its separate graceful shutdown and connection-handler cleanup policy. Constructor and configuration loading never start detached ACME work.

The HTTP boundary requires directly terminated TLS, a configured Host consistent with SNI, and matching HTTPS origin (including the effective port) whenever an Origin is supplied. Missing Origin is rejected for non-GET/HEAD methods and upgrades; safe browser navigations may omit it. Cross-site requests into the reserved internal namespace are rejected. Forwarded headers do not override these checks. Absolute-form proxy requests, CONNECT and encoded/dot/backslash path aliases are rejected before routing; no path cleaning can turn them into another flow.

Responses use `frame-ancestors 'none'`, `X-Frame-Options: DENY`, a restrictive same-origin CSP, `no-store`, `nosniff`, HSTS without an implicit subdomain/preload commitment, and same-origin opener/resource policies. There is no CORS grant, cookie-based authentication, asset serving or working WebSocket protocol yet. The password API adds the stricter limits below; future interactive/streaming protocols still need their own controls.

Before opening TLS or ACME state, runtime paths are canonicalized on a cloned configuration. TLS files/ACME storage are checked against session storage, audit/recording state and static SSH/SFTP inputs. Public asset directories and custom CSS/JS inputs cannot overlap these protected paths; existing hard-link aliases are checked in addition to canonical symlink paths. Disabled HTTP does not inspect its unused paths. Per-file asset containment checks are still required when serving is implemented.

TLS certificate and ACME account/certificate public keys must be distinct from known static SSH keys, audit signing identities, SFTP identities and configured audit encryption recipients, including configured recipients of disabled auditlogs. Copied key material at unrelated paths is not an exemption; audit best-effort policy cannot waive this HTTPS safety check. New ACME keys and cached/renewed certificates are checked before use/publication. Audit decryption private keys are never requested by the HTTPS endpoint.

## Initial discovery and password API

`GET /` shows only configured `discoverAsSlug` links for the current host, in configuration order, as a small static English page. `Accept: application/json` requests discovery/selection metadata instead. `GET /<slug>` returns JSON selection metadata, including `requestUser`; these are **not** authorizations. `HEAD` returns headers only. The final React frontend will replace this interim presentation.

The published-slug priority, general/HTTP requirements, host/slug matching, `http.enabled` and `http.requestUser` are enforced by the **same authorizer facade** used for SSH, with an explicit HTTP selection. A published flow's rejected credentials or requirements cannot fall through to another flow. An undiscovered slug retains normal configuration-order matching. Disabled name collection requires an empty `user`; the server never substitutes the principal for `.remote.user`. Discovery cannot predict whether a name, credential or environment will be accepted.

The initial JSON endpoints are:

| Method and path | JSON body | Purpose |
| --- | --- | --- |
| `POST /_bifroest/api/v1/login/password` | `{"slug":"Work","user":"alice","password":"..."}` | Verify through the existing password authorizer and issue a scoped ephemeral permission. All three string fields are required; empty values remain subject to configured authorization. |
| `POST /_bifroest/api/v1/access` | `{"slug":"Work"}` | With `Authorization: Bearer <accessToken>`, recheck the permission, session, identity, target and environment. It does not renew its expiry or touch session last access. |
| `POST /_bifroest/api/v1/logout` | `{"slug":"Work"}` | With the same bearer proof, remove only that permission and close its attached web connections. No session/environment disposal and no session-wide SSH disconnect. |

All these requests require the boundary's same HTTPS Origin. Query parameters, unknown/duplicate/null/non-string JSON fields, trailing JSON, encoded request bodies and non-JSON content are rejected. Login bodies are limited to 16 KiB, names to 256 bytes and passwords to 4096 bytes. Internal authentication errors are not returned to the client. Private keys and passphrases are not accepted fields; later imported-key support must sign locally in tab memory.

A successful login returns `status`, `accessToken`, `expiresAt`, `scope` (canonical HTTPS origin including port and exact slug), the mapped `principal`, `environment` (`terminal` or `management`) and `terminalAvailable: false`. The opaque token contains 256 random bits and is indexed by its SHA-256 hash only in server memory. Its permission also pins the verified authorization/flow, session and pure target digest, independently of persistent session ownership. It expires after ten minutes, does not slide and does not survive a service restart. **This is not RememberMe.** A future browser client must keep it only in tab memory: never URLs, cookies, LocalStorage or IndexedDB. Possession remains a bearer capability and is not protection against trusted same-origin JavaScript.

Anonymous logins get independent sessions and permissions; the label `anonymous` never merges them. The independent token may authorize a fresh connection only to its own stored session/target. A known session ID, user name or discovery link is never accepted as proof. This does not yet add anonymous web-to-SSH resumption.

There are at most 64 concurrent API operations, four per direct peer IP, 12 password starts and 120 API requests per peer per minute, 1024 tracked peers and 1024 live/retained permissions. Forwarded headers cannot change the peer or authority. Limits fail closed with 429 and `Retry-After`; expired inactive entries are reclaimed lazily. Read deadlines bound request bodies to the shorter of 20 seconds and configured `readHeaderTimeout`; authorization receives a 20-second cancellation context. Shutdown cancels/drains admissions, including slow body reads, before closing repositories. These fixed initial safeguards are not a substitute for future WebSocket/interactive/connection limits.

Login itself does not provision an environment, renew session access or reserve a connection quota. The internal connection adapter revalidates permission/target and acquires the same neutral session quota as SSH for **each new execution connection**. It rejects reattachment. Expiry prevents new access but leaves existing authenticated executions alone; an expired permission retained for active children can still prove logout. Explicit logout closes only its own children, while session limits/disposal and session-wide revocation remain stronger controls. There is not yet a public terminal or Management execution endpoint.

Tests cover a real TLS/HTTP2 password login and a real SSH login selecting one stored session, plus scoped anonymous proofs, quota acquisition, expiry/logout isolation, target changes, strict/best-effort audit, bounded admission, cancellation and shutdown during a withheld request body. They are not a browser, WebSocket, or real shared-container end-to-end test.

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
:   Positive HTTP request-header timeout; the same budget also bounds initial HTTP request-body reads. Responses do not have a fixed write timeout, so future streaming handlers can own their lifetime limits.

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
:   Ordered explicit certificate sources. Runtime preparation prefers the first matching explicit certificate before consulting ACME for remaining allowed domains. Full explicit coverage does not open ACME storage or contact the CA. A list can cover multiple domains; its actual certificate contents are not inspected by configuration validation.

<<property("acme", "ACME", "#acme", id_prefix="tls-", heading=3)>>
:   Optional automated certificate source. It remains disabled unless explicitly enabled, even if no explicit certificate is configured.

### Certificate

Each entry under `http.tls.certificates`:

<<property("certificateFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
:   Local PEM certificate chain file.

<<property("privateKeyFile", "File Path", "../data-type.md#file-path", required=True, id_prefix="certificate-", heading=4)>>
:   Local PEM private key file, **not inline private key material**. Configuration errors do not echo rejected key-field values.

### TLS preparation core

The server-side `pkg/https` package provides the following checks, with separate core tests and real service/listener integration tests:

- Bounded certificate/key file reads, leaf/key matching, validity intervals, server-authentication usage, and signatures/order of supplied certificate-chain entries. Every configured pair must be valid and cover at least one allowed domain; a broken explicit pair does not silently fall back to ACME.
- Self-signed and private-CA certificates without requiring the server's OS public root store. The final supplied certificate is the explicit chain-validation anchor; a root need not be sent in a bundle. An omitted issuer cannot be verified locally. **Browser trust, missing-issuer resolution and revocation remain client checks**, not properties asserted by the server's preparation result.
- The existing private-file protection policy: Unix service ownership and no group/other access; on Windows a protected owner/SYSTEM access-control list. Explicit paths are resolved before loading. The loader does not repair permissions, generate missing keys or overwrite files. RSA keys require at least 2048 bits, ECDSA at least 256 bits; Ed25519 is also supported.
- SNI selection strictly limited to configured domains, even when a wildcard/SAN certificate covers more. Missing SNI is rejected for DNS names and ambiguous selections. Because browsers omit SNI for IP URLs, a sole explicitly configured IP literal can be selected without SNI; the HTTP boundary still enforces Host/SNI/Origin rules.
- An atomic initial readiness barrier: normal TLS handshakes fail until **all** configured domains have valid certificates. Before readiness, only an actively installed, domain-bound `acme-tls/1` proof is available. ClientHello requests never trigger certificate acquisition.
- Strict, temporary TLS-ALPN-01 proof validation: a single DNS name, the critical ACME SHA-256 identifier extension, self-signature and matching key. Cancellation/timeout/close invalidates proofs; releasing an older proof cannot remove a newer one. Proof certificates cannot become application certificates.
- Context-bound preparation and shutdown with no detached acquisition/renewal goroutines. TLS uses a minimum of TLS 1.2. Session tickets are initially disabled so resumption cannot bypass readiness or certificate-lifetime checks; supplied-chain expiration is rechecked for new handshakes.

Tests include actual TLS, HTTP/2 and TLS-ALPN proof handshakes, private CA and IP cases, joint SSH/HTTPS startup/failure/cancellation, bounded HTTP shutdown, and path/key separation. ACME tests exercise issuance, persistent account/certificate storage and renewal against a local test CA through a real HTTPS listener; no public CA is contacted. Password HTTP login is covered separately above; interactive browser authentication remains pending.

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

    This must not be an asset, session, audit/recording directory or overlap static credential inputs. The backend creates and checks private storage as described below; service preparation enforces path separation before opening it.

### ACME backend and renewal

The server-side backend uses the context-aware `acme.Client` directly. It does not use `autocert.Manager`, whose detached acquisition contexts and unexposed renewal timers do not fit the joint startup/shutdown lifecycle.

- Only configured DNS domains can be requested, using **TLS-ALPN-01 only**. An IP literal needs an explicit certificate; HTTP-01, DNS-01, wildcard issuance and incoming-host-triggered issuance are not implemented. Order/authorization identifiers, the CSR, the returned certificate/key pair and the complete supplied chain are checked before persistence.
- Storage has a private base directory and a separate `ca-<SHA-256 of directoryUrl>` subdirectory per CA directory. Newly generated account and certificate keys use ECDSA P-256. `account.pem` stores the account key; `certificate-<SHA-256 of canonical domain>.pem` stores a certificate key and chain together. Account keys and certificate keys are separate. A change of CA directory therefore does not reuse another CA's account or certificate cache.
- New private files use the existing protected temporary-file and atomic-install helpers. They are flushed before installation; certificate and key are replaced as one unit. Existing directory ownership/modes or protected Windows ACLs are validated rather than repaired. Reads reject symlink/nonregular, multiply linked, oversized or insecure files and malformed PEM state; state files and ACME response bodies are bounded to 2 MiB, with the TLS core's stricter chain limits applied additionally.
- A new account key is generated only in an empty CA-specific store. Existing account keys are never silently replaced. Missing account keys alongside stored state, corrupt keys, or an account-key change while running make new issuance fail; restore the intended account state rather than expecting automatic account replacement. A still-valid cached certificate can be loaded without contacting the CA or needing account registration. The private store belongs to the service operator; it is not a defense against malicious code running as that same OS identity.
- Initial preparation reuses valid stored certificates even when renewal is already due, so an unavailable CA does not prevent startup with valid material. Missing or expired certificates require successful issuance. Failure for any initial domain prevents all normal TLS handshakes; a later retry can reuse already persisted certificates without issuing them again.
- `TLS.RunRenewal` is a blocking loop owned by the caller, not an automatically detached goroutine. Renewal becomes due one third of the supplied chain's effective lifetime before expiry, capped at 30 days before expiry. Replacements are checked and persisted before publication; a newly issued certificate that already requires renewal is rejected. During validation, the existing valid application certificate remains usable alongside the temporary proof.
- Failed renewal retains the existing live certificate/key. Issuance or validation failure does not replace cached material; a storage error can occur after an atomic installation, in which case a later retry revalidates the stored result. Per-domain retries wait at least 30 minutes and honor longer ACME rate-limit `Retry-After` values; hidden request retries do not repeatedly create orders. Existing certificates are never served past their validity interval. Stopping renewal does not dispose sessions or terminate already authenticated connections.
- Each operation is bounded by its caller context and `startupTimeout`; cancellation removes active proofs. Closing the backend cancels and drains active operations and closes its idle HTTP connections and storage handles. ACME endpoints, including redirects, must remain HTTPS without embedded credentials. Errors are safe for logs; their preserved causes must not be separately logged without redaction.

The local test CA verifies request signatures and nonces, CSR signatures and actual account-bound TLS-ALPN-01 proofs. Tests cover multiple domains, failure of a later domain, restart with an offline CA, expired-cache reissuance using the same account, renewal, rate limits, corrupt/private storage, active-challenge cancellation and timeout/close. Listener tests additionally serve these proofs over the real HTTP server. This does **not** yet provide a usable browser login or workspace.

## RememberMe

Under `http.rememberMe`:

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="6h", id_prefix="rememberme-", heading=3)>>
:   Positive **sliding unused timeout** for explicitly opted-in browser bindings. Successful proof of possession extends it. Expiry requires regular login again; it does not terminate already authenticated connections, dispose sessions/containers, or override shorter session limits and revocations. This setting alone neither creates a binding nor implements browser RememberMe.

## Schema examples

These are complete, parser-checked configuration examples for HTTPS. Actual startup requires the indicated certificate/key files or successful ACME issuance for every domain. The examples' OIDC browser login and Management UI remain unimplemented; the initial HTTP adapter supports password authorization only.

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
