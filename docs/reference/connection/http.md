---
description: HTTPS listener, certificate and browser transport configuration.
toc_depth: 5
---
# HTTP / HTTPS

!!! warning "Authentication and terminal protocols; no browser workspace UI yet"
    Enabled HTTPS serves published access links, flow metadata, password/keyboard-interactive/OIDC-device/public-key authentication, browser-binding enrollment/resumption/revocation APIs and a WebSocket terminal protocol through the same authorizers/session selector and execution driver as SSH. The persistent browser client/explicit opt-in UI, React frontend/imported-key UI, assets and browser Management actions remain unimplemented. Local password/interactive resumption is deliberately unavailable until native account-policy rechecks are implemented. Unknown internal routes return 404. Keep HTTP omitted or disabled unless you intend to expose these partial browser-facing protocols.

HTTP is a separate incoming transport for the same [flows](../flow.md), not SSH tunneled over WebSocket. Omission of the root `http` block means disabled. Merely configuring domains, TLS or customization does not enable it. When the endpoint is available, all flows are HTTP-eligible by default unless their individual `http.enabled` is false; `ssh.enabled` remains independent.

Configuration loading performs no certificate-file reads, key generation, ACME requests or asset-file reads. The schema supports explicit PEM certificate/key pairs, ACME, or both; an explicitly selected [dummy certificate](#dummy-tls-for-local-testing) is a separate test-only alternative. The [TLS preparation core](#tls-preparation-core) and [ACME backend](#acme-backend-and-renewal) are integrated into the [joint listener lifecycle](#joint-listener-lifecycle). Schema validation alone does not prove certificate availability or port binding.

## Joint listener lifecycle

All configured SSH and HTTPS TCP inputs are bound before any challenge or application transport is served. A binding failure closes every previously bound input without starting ACME acquisition. Service preparation can already have created SSH keys and other persistent service resources; failure does not delete that state.

The HTTPS listeners then serve only active TLS-ALPN-01 proofs while initial certificate preparation runs. Normal TLS handshakes and SSH serving remain blocked until **every configured domain** has valid material. A failed domain, acquisition timeout, cancellation or unexpected listener exit cancels preparation, removes proofs and closes all inputs. Successfully persisted certificates remain available for the next start.

After readiness, SSH and HTTPS run together, with a caller-owned ACME renewal loop. Unexpected termination of **either** transport stops the whole service; a half-running deployment is not considered successful. Shutdown stops accepting, cancels acquisition/renewal, drains HTTP for at most `gracefulShutdownTimeout` and then closes remaining HTTP connections. SSH retains its separate graceful shutdown and connection-handler cleanup policy. Constructor and configuration loading never start detached ACME work.

The HTTP boundary requires directly terminated TLS, a configured Host consistent with SNI, and matching HTTPS origin (including the effective port) whenever an Origin is supplied. Missing Origin is rejected for non-GET/HEAD methods and upgrades; safe browser navigations may omit it. Cross-site requests into the reserved internal namespace are rejected. Forwarded headers do not override these checks. Absolute-form proxy requests, CONNECT and encoded/dot/backslash path aliases are rejected before routing; no path cleaning can turn them into another flow.

Responses use `frame-ancestors 'none'`, `X-Frame-Options: DENY`, a restrictive same-origin CSP, `no-store`, `nosniff`, HSTS without an implicit subdomain/preload commitment, and same-origin opener/resource policies. There is no CORS grant, cookie-based authentication or asset serving. Authentication and terminal protocols add the limits below.

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
| `POST /_bifroest/api/v1/logout` | `{"slug":"Work"}` | With the same bearer proof, revoke its browser binding if linked, removing all permissions/children linked to that binding; otherwise remove only this permission and its children. No sibling-binding/grant or SSH disconnect and no session/environment disposal. |

All these requests require the boundary's same HTTPS Origin. Query parameters, unknown/duplicate/null/non-string JSON fields, trailing JSON, encoded request bodies and non-JSON content are rejected. Login bodies are limited to 16 KiB, names to 256 bytes and passwords to 4096 bytes. Internal authentication errors are not returned to the client. Private keys and passphrases are not accepted fields; later imported-key support must sign locally in tab memory.

A successful login returns `status`, `accessToken`, `expiresAt`, `scope` (canonical HTTPS origin including port and exact slug), the mapped `principal`, `environment` (`terminal` or `management`) and `terminalAvailable` (true for terminal flows, false for Management). The opaque token contains 256 random bits and is indexed by its SHA-256 hash only in server memory. Its permission also pins the verified authorization/flow, session and pure target digest, independently of persistent session ownership. It expires after ten minutes, does not slide and does not survive a service restart. **This is not RememberMe.** A future browser client must keep it only in tab memory: never URLs, cookies, LocalStorage or IndexedDB. Possession remains a bearer capability and is not protection against trusted same-origin JavaScript.

Anonymous logins get independent sessions and permissions; the label `anonymous` never merges them. The independent token may authorize a fresh connection only to its own stored session/target. A known session ID, user name or discovery link is never accepted as proof. This does not yet add anonymous web-to-SSH resumption.

There are at most 64 concurrent API requests, four per direct peer IP, 12 login/binding-proof starts (across all methods) and 120 API requests per peer per minute, 1024 tracked peers and 1024 live/retained web permissions. Pending logins, binding proofs and terminals have additional limits below. Forwarded headers cannot change the peer or authority. Limits fail closed with 429 and `Retry-After`; expired inactive entries are reclaimed lazily. Read deadlines bound request bodies to the shorter of 20 seconds and configured `readHeaderTimeout`; non-streaming API writes also have a 20-second deadline. Password/claim requests receive a 20-second cancellation context; multi-step authorizers have the independent lifetime below. Shutdown cancels/drains admissions, including slow body reads/writes, before closing repositories.

Login itself does not provision an environment, renew session access or reserve a connection quota. The connection adapter revalidates permission/target and acquires the same neutral session quota as SSH for **each new execution connection**. It rejects reattachment. Expiry prevents new access but leaves existing authenticated executions alone; an expired permission retained for active children can still prove logout. Explicit logout closes only its own permission/binding's children, while session limits/disposal and session-wide revocation remain stronger controls. Terminal execution is available through the WebSocket protocol below; structured browser Management actions remain pending.

Tests cover a real TLS/HTTP2 password login and a real SSH login selecting one stored session, plus scoped anonymous proofs, quota acquisition, expiry/logout isolation, target changes, strict/best-effort audit, bounded admission, cancellation and shutdown during a withheld request body. Terminal protocol tests are described below; neither set is a browser or real shared-container end-to-end test.

## Interactive and public-key login protocol

These endpoints use the same boundary, flat string-only JSON parser and login-start/request budgets as the password API:

| Method and path | JSON body | Purpose |
| --- | --- | --- |
| `POST /_bifroest/api/v1/login/interactive` | `{"slug":"Work","user":"alice"}` | Start keyboard-interactive authorization, including the existing OIDC Device Authorization Flow. |
| `POST /_bifroest/api/v1/login/public-key` | `{"slug":"Work","user":"alice","publicKey":"<base64>"}` | Start a possession challenge for an SSH wire-format public key or certificate, encoded as canonical standard Base64. No private key, PEM, authorized-keys text or passphrase is accepted. |
| `POST /_bifroest/api/v1/login/poll` | `{"slug":"Work"}` | Read the outstanding step or claim a completed login exactly once. |
| `POST /_bifroest/api/v1/login/reply` | `{"slug":"Work","sequence":"1",...}` | Acknowledge an info/error step, answer a prompt, or submit one possession signature. |
| `POST /_bifroest/api/v1/login/cancel` | `{"slug":"Work"}` | Cancel an unconsumed login attempt, not a session or an already-issued web permission. |

Start returns 202 with `status: "pending"`, `attemptToken`, `expiresAt`, `pollAfterMillis: 1000` and an optional `step`. Poll/reply/cancel require `Authorization: Bearer <attemptToken>`. This independent 256-bit `bwl1.` proof is indexed only by hash in server memory and binds the exact HTTPS origin, slug, original requesting user/key and direct peer IP. It cannot authenticate access/logout/terminal requests, and an `accessToken` cannot control a login attempt. Keep both proofs only in tab memory, never URLs or persistent browser storage. A network/peer change during a login requires a new attempt.

Polling returns 200 with `status: "pending"` and at most one outstanding step. There is no unbounded message queue. A step has an exact string `sequence`, a `kind` and an `echo` flag:

- `info` / `error`: show `message` as **plain text**, never HTML or terminal/shell input. Reply with only `slug` and `sequence` to acknowledge it. OIDC's device URL/user-code instruction uses this path; no browser redirect flow or OAuth token is sent to the browser. Acknowledgement lets the existing server-side device polling continue.
- `prompt`: show the plain-text message and honor `echo`. Reply with `slug`, `sequence` and an `answer` string of at most 4096 bytes. Secret answers are not echoed in any API response. This is a login dialog, not task stdin.
- `public-key`: sign the decoded `challenge` bytes locally and reply with `slug`, `sequence` and a `signature` string as described below. Never send the selected private key or passphrase.

Successful replies return 202; the next poll reads progress. A sequence can be answered once, and stale/duplicate replies return 409. Wrong field sets and malformed JSON are rejected without supplying credentials to an authorizer. After a worker completes, exactly one poll may claim its result through the same session/target/environment checks, Authentication-Completed audit and ephemeral web-permission issuance as password login. It returns the normal authorized/access-token response. Parallel polls cannot mint duplicate grants or cancel the winning claim. Consumed results are not replayable; if the claim response is lost, start a new regular login. Internal errors remain redacted.

There are at most 64 retained/running login attempts and four per direct IP, separately from request concurrency. Attempts expire after 90 seconds without valid polling/replies, with a hard lifetime of ten minutes for interactive/OIDC and two minutes for keys. Normal completion of the start HTTP request does not cancel the logical login. Explicit cancel, idle/hard expiry and shutdown do cancel prompts and IdP requests. A cancelled worker keeps its capacity until it **actually returns**; cancellation relies on authorizers honoring their context, rather than abandoning goroutines. Shutdown drains those workers before closing repositories. Cancel/expiry never dispose sessions: an authorizer that has already verified credentials may have allocated session state, but cannot issue a late web permission from a cancelled/unclaimed attempt.

Interactions are bounded to 32 steps, 8 KiB per message and 32 KiB of message text per attempt. Polling does not extend the hard lifetime or renew session access. These limits and timers do not implement RememberMe or a terminal execution lease.

### Public-key possession boundary

The server accepts Ed25519, RSA from 2048 through 8192 bits, and NIST P-256/P-384/P-521 ECDSA keys, including SSH user certificates over those keys. DSA, RSA/SHA-1 possession signatures and hardware/security-key formats are not enabled by this initial protocol. Existing SSH configuration and key handling are unchanged.

`step.challenge` is canonical standard Base64 of the exact bytes to sign: the domain-separating prefix `bifroest-http-public-key-v1` followed by a zero byte and server-generated JSON containing origin/effective port, slug, requesting user, connection ID, the exact key/certificate fingerprint, an independent 256-bit nonce and expiry. Sign the supplied bytes, not a reconstructed JSON document. A Go-compatible client uses `ssh.Signer.Sign` (RSA: `ssh.AlgorithmSigner.SignWithAlgorithm` with `rsa-sha2-256` or `rsa-sha2-512`), encodes the resulting `ssh.Signature` with `ssh.Marshal`, then standard Base64. This is a signature encoding, not an SSH transport or tunnel.

The server verifies against its stored challenge and exact key, rejects trailing signature data and unsupported algorithms, and consumes an accepted proof reply even if the signature is wrong. Only after a valid fresh signature may the trusted adapter assert `PublicKeyVerified()` and call the existing public-key authorizer. Certificate CA signatures alone cannot allocate a session or authenticate; CA/principal/type/time/critical-option checks and configured-key/remembered-key policies still run after proof. Certificate policy is not broadened: options rejected by the existing checker remain rejected. Configured forced-command/environment/PTY restrictions are retained in the issued authorization, and regular browser key login does not silently register a key for SSH RememberMe.

OIDC uses the existing verified issuer/subject, token verification, session locks, refresh/pending/lost-access rules and claim separation. A fresh device login cannot overwrite an existing rotating refresh chain. HTTP permission issuance requires a valid normalized identity, never a guessed requesting name or decoded JWT fallback. Audit records distinguish `keyboard-interactive` and `public-key`; OIDC additionally retains its existing authorization kind.

Tests exercise acknowledged multi-step messages and secret/echo prompts, replay/scope/peer rejection, one-time concurrent claims, late cancellation, capacity retention, strong signature formats and existing certificate rules. Real TLS/HTTP2 interactive/key logins and an SSH login select one persisted session. A local TLS IdP with signed ID tokens exercises device login, retained rotated grants and cancellation of a real outstanding token request. This remains server/protocol coverage, not a browser imported-key UI or shared-container E2E result.

## WebSocket terminal protocol

`GET /_bifroest/api/v1/terminal` accepts an HTTP/1.1 WebSocket upgrade with exactly the subprotocol `bifroest-terminal.v1`. Ordinary APIs continue to support HTTP/2; extended CONNECT/HTTP2 WebSockets are not implemented. The normal direct-TLS/Host/SNI/same-HTTPS-Origin boundary runs before upgrading. Query parameters and upgrade request bodies are forbidden. No compression is negotiated.

Browser WebSocket APIs cannot supply an ordinary Authorization header. The access proof is therefore sent only in the **first text message**, within five seconds of upgrade, never in the URL, cookies or subprotocol:

```json
{"type":"open","slug":"Work","accessToken":"bwa1.…","task":"shell","pty":{"term":"xterm-256color","columns":80,"rows":24},"environment":["LANG=en_US.UTF-8"]}
```

For exec, use `"task":"exec","command":"..."` instead; shell requests must omit `command`. `pty` and `environment` are optional. The empty slug selects the root. No client-selected session/connection ID, subsystem, private key or passphrase is accepted. Objects have exact case-sensitive field sets: unknown/duplicate/null fields, non-UTF8 controls and trailing JSON fail closed. Commands are limited to 4096 bytes without NUL. Terminal names are 1–128 ASCII letters/digits or `-_.+`; columns/rows must be positive uint16 values and optional `widthPixels`/`heightPixels` uint32 values. At most 32 environment strings are accepted, each `NAME=value`, with ASCII identifier names of at most 128 bytes, values of at most 2048 bytes, 8 KiB total and no NUL or case-insensitive duplicate names. Existing server/key/client environment-layer and forced-command policies still decide the effective environment/command.

The server rechecks the scoped proof, authorization, session, identity, effective target and environment before acquiring a fresh shared connection quota. It replies `{"type":"ready","connectionId":"..."}` after registration, **not** as a promise that provisioning or execution will succeed. Each socket owns exactly one new shell/exec, with the shared task/audit/recording driver; reconnect or reload never reattaches to an old execution. Management flows are rejected here, not routed through CLI subprocesses or SSH tunnels. Their UI/protocol remains separate work.

After open:

| Direction / frame | Payload | Meaning |
| --- | --- | --- |
| Client binary | Raw bytes, no channel prefix | Task stdin; bytes are not UTF8-decoded. |
| Client text | `{"type":"eof"}` | Drain already-queued input, then input EOF; output, controls and heartbeat continue. Repeated EOF or later stdin is invalid. |
| Client text | `{"type":"resize","columns":100,"rows":30}` | PTY-only resize, with the same dimensions and optional pixel fields as open. |
| Client text | `{"type":"signal","signal":"TERM"}` | Supported symbolic target signal; `SIGTERM` aliases normalize. No native numeric signals. |
| Server binary | One channel byte (`0` stdout/terminal, `1` stderr), then raw bytes | Ordered bounded output chunks. PTY backends may merge stderr themselves. |
| Server text | `{"type":"exit","status":0}` | Validated uint32 task status, after recording seal and final task audit, followed by normal WebSocket close (1000). |
| Server text | `{"type":"error","code":"execution-failed"}` | Redacted failure, never raw backend/authentication diagnostics or a successful exit. Connection loss or strict audit/capture failure may close without a final message. |

EOF is not disconnect; socket loss cancels the owning execution. Successful exit is authoritative only when an `exit` message is received. An abnormal close must not be treated as status zero. No session/environment disposal occurs merely because a connection ends. Grant expiry denies new connections but does not terminate authenticated ones; own logout, session limits/disposal and registry revocation remain effective.

### Terminal resource and lifetime limits

- At most 64 upgrading/live terminal sockets globally and eight per direct peer IP, independently of shared per-session connection limits. Handshake/open/registration also uses the API concurrency and request-rate budgets above; authenticated terminals release the non-streaming worker slot. Capacity is retained through execution/worker cleanup, not just until disconnect.
- At most 16 KiB per complete incoming message, 1 KiB per post-open text control, four queued stdin messages (64 KiB plus the current read), and 16 queued resize/signal controls each. Full queues close the connection rather than dropping input or growing without bound.
- Per socket, fixed one-second inbound budgets of 128 messages, 32 text/Ping/Pong controls and 64 KiB of decoded message payload. An additional 96 KiB/second WebSocket wire-read budget bounds empty/tiny fragmented-frame floods before a complete message exists. These are abuse limits, not a bulk-file-transfer protocol; clients must pace input.
- Output is written synchronously in chunks of at most 16 KiB including channel byte, with a five-second write budget per message and no detached output queue. Backpressure/deadline or forced close cancels the execution and closes the underlying socket without waiting for a TLS goodbye write.
- A server Ping with a fresh nonce is sent every 15 seconds when no previous Ping is outstanding. Only its matching Pong extends the 45-second receive deadline; unrelated data and unsolicited Pongs do not. No browser unload callback is required. Heartbeats are transport liveness only: they do not renew session idle activity, ephemeral grant expiry or RememberMe.
- Reader, heartbeat and signal-forwarding workers are owned/drained. Shutdown cancels even sockets that never sent open, closes authenticated transports and drains execution before closing repositories.

Tests use real HTTPS/WebSocket connections and signed filesystem recordings for raw stdin/stdout/stderr, EOF, resize/signal capture, separate executions in one session, strict recording failure, redacted backend errors, proof/Origin/query rejection, quotas, expiry/logout/revocation, oversized/fragmented floods, bounded queues, slow-reader write timeout, missing Pong, abandoned open and shutdown. A real incoming SSH execution and two WebSocket executions use the same persisted session with the built-in Dummy backend. This is not a browser UI, Windows/ConPTY runtime or real shared Docker/Kubernetes container E2E claim.

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
:   Certificate sources. An enabled endpoint requires configured certificates, explicitly enabled ACME, or explicit test-only `tls.dummy: true`.

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

<<property("dummy", "bool", default=False, id_prefix="tls-", heading=3)>>
:   Explicitly generate an ephemeral self-signed test certificate during service preparation and log a **WARN**. Cannot be combined with `certificates` or enabled ACME. There is no automatic fallback to dummy TLS. See [Dummy TLS for local testing](#dummy-tls-for-local-testing).

<<property("certificates", array_ref("Certificate", "#certificate"), id_prefix="tls-", heading=3)>>
:   Ordered explicit certificate sources. Runtime preparation prefers the first matching explicit certificate before consulting ACME for remaining allowed domains. Full explicit coverage does not open ACME storage or contact the CA. A list can cover multiple domains; its actual certificate contents are not inspected by configuration validation.

<<property("acme", "ACME", "#acme", id_prefix="tls-", heading=3)>>
:   Optional automated certificate source. It remains disabled unless explicitly enabled, even if no explicit certificate is configured.

### Dummy TLS for local testing

`http.enabled: true` together with `http.tls.dummy: true` explicitly requests a newly generated ECDSA P-256 key and self-signed certificate. The service emits a WARN naming `http.tls.dummy=true` and explaining that the material is for testing only and not browser-trusted. Merely parsing configuration, disabling HTTP, omitting the flag or setting it to false never generates a dummy certificate.

The key/certificate stay only in memory, are new for every service preparation and are valid for 24 hours (with a five-minute not-before allowance). They cover only the finite configured DNS/IP domains, including IPv6 SANs; no wildcard or arbitrary-host issuing is added. There is no disk persistence, ACME request, renewal or OS/browser trust-store installation. After expiry, restart the test instance to generate new material. TLS readiness, Host/SNI/Origin enforcement and key-role separation remain active.

Browsers will show a certificate warning. Any manual exception or a command such as `curl --insecure https://localhost:8443/` is a deliberate **local test-client** choice, not trust granted by Bifröst; do not use this mode with production credentials. Own certificate pairs or enabled ACME alongside `dummy: true` are configuration errors, so broken explicit certificate material can never silently become a dummy certificate. Other normal service prerequisites and writable state paths still apply.

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

Tests include actual TLS, HTTP/2 and TLS-ALPN proof handshakes, private CA and IP cases, joint SSH/HTTPS startup/failure/cancellation, bounded HTTP shutdown, and path/key separation. ACME tests exercise issuance, persistent account/certificate storage and renewal against a local test CA through a real HTTPS listener; no public CA is contacted. The authentication APIs are covered separately above; the browser UI remains pending.

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
:   Positive **sliding unused timeout** for explicitly opted-in browser bindings. Successful fresh possession proof, current authorization and audit checks extend it. Expiry requires regular login again; it does not terminate already authenticated connections, dispose sessions/containers, or override shorter session limits and revocations. This setting alone does not enroll a browser or provide the still-pending persistent browser client.

### Enrollment, resumption and revocation protocol

These server APIs are implemented; **the explicit opt-in UI and encrypted IndexedDB client are not**. Enabling HTTP, regular login or configuring `rememberMe.idleTimeout` does not silently enroll a browser. An eventual browser client must generate independent non-exportable signing and encryption keys only after explicit opt-in. Imported primary private keys/passphrases must remain exclusively in the current tab.

All paths below are `POST /_bifroest/api/v1/remember/<action>`, behind the same HTTPS Origin, exact string-only JSON parser, request deadlines and admission limits as login:

| Action | JSON body | Authorization |
| --- | --- | --- |
| `enroll` | `{"slug":"Work","publicKey":"<base64 P-256 point>"}` | A live `Bearer bwa1.…` permission from regular primary login, not an already-linked or resumed permission. |
| `resume` | `{"slug":"Work","flow":"work","sessionId":"…","bindingId":"bbr1.…"}` | No Authorization header. These identifiers only select a binding; they do not authenticate. |
| `revoke` | Same selector as `resume`. | No Authorization header. Expired bindings can still be selected for possession-proven revocation. |
| `prove` | `{"slug":"Work","signature":"<base64 P1363 signature>"}` | `Bearer bwr1.…` from exactly one preceding start response. |

A start returns 202 with `status: "proof-required"`, `attemptToken`, `challenge` (canonical standard Base64 of the exact bytes to sign) and `expiresAt`. The independent random 256-bit `bwr1.` token controls only that one-minute proof attempt, indexed by hash in server memory and pinned to Origin/effective port, slug and direct peer IP. It cannot execute a task or replace a `bwa1.` access token. Keep it in tab memory only, never URLs, cookies or persistent storage. At most 64 proof attempts and four per peer are retained, separately from login workers; starts consume the shared twelve-starts-per-minute budget. Claims retain capacity while current authorization completes and drain during shutdown.

Sign the decoded bytes with the independent browser key using ECDSA P-256/SHA-256 and return canonical standard Base64 of the 64-byte `r || s` signature. This is **not** the SSH public-key login wire/signature format. Correctly scoped verification attempts are consumed even on wrong signatures or expiry; a proof response cannot be replayed. Concurrent challenges pin the stored binding revision, so at most one can renew that revision. A lost claim response is not replayable; create a fresh challenge, or log in regularly if an enrollment response was lost.

Successful enrollment returns 201 with `status: "remembered"`, `flow`, `sessionId`, `bindingId` and the unused `expiresAt`. Only then does the server persist the public-key binding and link the primary permission to it. Resume returns the normal authorized response with a **new ten-minute `bwa1.` permission**, not a session lease or reattachment. Before issuance the authorizer facade rechecks current HTTP selection, published-slug priority and requirements; authorizer-owned code re-evaluates credential/key/certificate policy and current claims, then the service checks session validity/revocation, normalized identity/principal, effective target, environment and audit policy. No saved Authorization rights snapshot becomes a new grant. OIDC uses the existing session lock, rotating grant, pending-verification and lost-access rules without extending an old verification deadline. Certificates must still be valid and trusted; forced-command, environment and PTY restrictions are recomputed from the exact primary key/certificate, not from another connection's session-creation evidence.

Simple, htpasswd, OIDC-device and None authorizers support their applicable primary methods; Bifröst delegation requires its exact currently valid certificate. Local authorization supports key/certificate bindings only. **Local password/keyboard-interactive enrollment and resume fail closed on Unix and Windows** until secretless native PAM/account/logon-policy rechecks are available: account-name/UID/SID lookup alone cannot replace them. Regular primary login remains available. Third-party authorizers require an explicit trusted `SessionResumer` capability; diagnostic `RestoreFromSession` does not opt them in.

Successful `revoke` returns 204 after durable binding removal and closes all linked web permissions/terminal children, never sibling bindings/grants or SSH connections. Ordinary `logout` has the same binding-scoped effect for an enrolled/resumed permission, and remains permission-scoped without a binding. Persistence failure is reported as 503, not acknowledged as durable logout; linked in-memory access is still closed. Binding expiry only denies future resumption, without terminating authenticated grants/connections or disposing the shared session/container. Session validity and session-wide revocation remain stronger controls.

Tests cover explicit proof-before-enrollment, replay/scope/peer/revision isolation, current selection/requirements/key/certificate restrictions, strict audit failures, shortened idle-policy expiry without revival, linked/sibling logout, failed durable logout, anonymous isolation and service restart with new ephemeral access. Real HTTPS/WebSocket tests execute with a resumed permission and revoke its children. A local TLS IdP verifies retained refresh rotation and access-loss rejection. These are server/protocol tests, not an IndexedDB, native Local account-policy or browser UI/shared-container E2E result.

### Binding storage and possession-proof core

The optional trusted `session.BrowserBindingSession` capability stores browser permissions separately from SSH remembered keys. The FS implementation uses the private `wb` session sidecar with schema `bifroest-browser-bindings-v1`. A record pins canonical HTTPS origin/effective port, exact slug, original possibly empty requesting name, normalized identity, effective target digest, a browser-generated P-256 **public** key and server-verified primary credential provenance (authorizer kind, method and, for key login, the exact public key/certificate). No primary secret or rights snapshot is persisted. Foundation-era records without credential provenance remain inspectable/revocable but cannot resume. The containing path supplies flow and session, and the file envelope must repeat those exact identifiers: copying a sidecar to another session/flow cannot transfer it. The random 256-bit `bbr1.` identifier is only a selector, not a bearer credential or proof of ownership. Anonymous bindings remain local to their own session and do not create shared anonymous associations.

Creation and use require a trusted post-verification caller. The storage API itself does not authenticate a browser or replace the authorizer/service boundary above. A separate eligibility check does not renew the binding or advance its revision, but persists an observed shorter-policy expiry even when an HTTP proof start is rejected before authentication. Binding/claim processing neither selects a sibling session nor allocates a replacement one.

The FS store checks the current session's expiry/disposal under the same repository lock as the binding update. Each successful use atomically advances a persisted revision and sets a new unused deadline; stale concurrent uses cannot both win. The effective eligibility deadline is the earlier of the persisted expiry and `lastUsedAt + currentIdleTimeout`, so shortening the configuration takes effect and increasing it cannot revive an already expired permission. Waiting for the repository lock cannot backdate a use. Creation can reclaim expired binding capacity. There are at most 16 records per session and 128 KiB of sidecar state; exact JSON parsing rejects duplicate, unknown, null, mistyped, malformed Unicode and trailing data. Reads require a stable, private, service-owned single-link regular file. Writes use protected temporary files and atomic replacement. Malformed/insecure state is not repaired or overwritten, and binding state protects broken session metadata from destructive automatic cleanup.

Binding creation, inspection, successful use, expiry and storage revocation never touch session last access, alter authorization/environment tokens, allocate/release execution quota, register an SSH remembered key, close existing connections or dispose a session/workload. Storage revocation removes only that binding; the HTTP layer additionally closes its linked web access as described above. Authorizer revalidation may independently refresh OIDC credentials under its existing policy. Audit events use the distinct `browser-remember-me` authentication method without changing artifact or evidence wire schemas.

The standard-library-only `pkg/browserauth` core supports independent browser-generated ECDSA P-256 keys: canonical standard Base64 of WebCrypto's 65-byte uncompressed public point, and fixed 64-byte IEEE-P1363 `r || s` signatures using ECDSA/SHA-256. Challenges have a `bifroest-browser-remember-v1` zero-terminated domain prefix followed by server JSON binding purpose (`enroll`, `resume` or `revoke`), origin/slug, flow/session, target, exact public key, fresh 256-bit nonce and a one-minute expiry. Existing-binding challenges also pin binding ID and revision; enrollment has neither yet. Sign the exact supplied bytes, never reconstructed JSON. Each in-memory challenge accepts at most one verification attempt, including failed/expired signatures. Neither an SSH signature nor a certificate CA signature is a browser RememberMe proof.

Tests cover restart persistence, atomic concurrent use/revocation, sliding and shortened idle deadlines, stale/expired use, session limits/disposal, anonymous isolation, unchanged session/tokens/quotas/SSH keys, bounded/strict/private storage and preservation during cleanup. An optional native Node/WebCrypto interoperability test generates separate non-exportable signing and AES-GCM keys, checks export denial and verifies its actual P-256 possession signature in Go (`BIFROEST_TEST_NODE` selects a required runtime). The core also cross-compiles for JS/WASM. This is not a complete browser RememberMe feature, an IndexedDB/non-exportability guarantee for browser profiles, or browser UI/E2E coverage; the persistent client, explicit opt-in UI and native Local password-account policy adapter remain pending.

### Browser storage/signing core (not connected to login or UI)

The TypeScript core under `web/` now implements explicit opt-in at its API boundary, independent non-exportable P-256 signing and AES-GCM encryption keys, and real IndexedDB structured-clone persistence. It stores keys before an enrollment request could create a server binding. Only the public origin/slug hash and a random local generation ID are plaintext record selectors; flow/session/binding metadata is encrypted with fresh AES-GCM IVs and authenticated record context. Primary secrets, ephemeral access/attempt tokens and authorization snapshots are not accepted metadata fields. Missing keys or corrupt/unsupported storage require regular login; there is no private-key export/import or memory-only persistence fallback.

Local generation compare-and-swap prevents concurrent enrollments/completions and stale deletion from replacing another tab's record. Pending records can sign enrollment only; completed records sign resume/revoke only after checking the exact challenge domain, purpose, scope, public key and binding, using the original supplied bytes. Local deletion alone is **not** server logout/revocation and must not be presented as such.

An actual headless Chromium suite checks non-exportability/export denial, encrypted records, scope/proof isolation, concurrent updates, corruption and unsupported storage. A separate owned temporary browser profile survives an actual browser-process restart; the restarted client signs a challenge supplied and verified by the Go `browserauth` core. These tests use a secure-context loopback HTTP fixture, not production HTTPS/authentication. They do not establish Windows/macOS profile protection, hardware binding, other browser-engine support, or login/UI E2E coverage. The native Go subprocess is a test helper only, never part of a web action.

Vite 8/Rolldown builds this dependency-free client library without Webpack; Node and browser automation are development/test tools only. Generated files are not yet embedded or served by Go. The HTTP client/orchestration, explicit opt-in UI, React/Mantine/xterm application, imported-key handling and release/SBOM/asset integration remain pending. See `web/README.md` in the source tree for native Windows-compatible development commands.

## Schema examples

These are complete, parser-checked configuration examples for HTTPS. Apart from the explicit dummy test case, startup requires the indicated certificate/key files or successful ACME issuance for every domain. OIDC device login and terminal execution are available through the protocols above; the browser/Management UI and structured browser Management actions remain unimplemented.

### Explicit dummy TLS for local testing

This example needs no TLS files or CA, but intentionally does not establish browser trust. Both transports remain jointly startup-critical.

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
