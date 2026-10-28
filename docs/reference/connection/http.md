---
description: HTTPS listener, certificate and browser transport configuration.
toc_depth: 5
---
# HTTP / HTTPS

!!! warning "Incremental browser UI; not a complete workspace yet"
    Built browser resources provide React/Mantine password, Keyboard-Interactive/OIDC device, local SSH-key/WASM, RememberMe recovery, xterm shell tabs, structured Management metadata, paged artifact catalogs, confirmed session actions and client-only artifact verification/decryption/export/playback through the same HTTPS boundary and authorizers as SSH. The separate terminal API supports shell/exec; the UI currently opens shells only. Release jobs include the browser bundle, notices and SPDX/CycloneDX inventory, but do not supply signed source provenance. Remaining forced-command equivalence is incomplete. Local password/interactive RememberMe is supported for the non-PAM Linux repository backend; PAM-backed and Windows native logon-policy resumption remain unavailable. Source-only direct Go builds without generated resources keep the SSH/HTTP APIs and discovery fallback, not an embedded UI. Keep HTTP omitted or disabled unless you intend to expose this incremental feature.

HTTP is a separate incoming transport for the same [flows](../flow.md), not SSH tunneled over WebSocket. Omission of the root `http` block means disabled. Merely configuring domains, TLS or customization does not enable it. When the endpoint is available, all flows are HTTP-eligible by default unless their individual `http.enabled` is false; `ssh.enabled` remains independent.

Configuration loading performs no certificate-file reads, key generation, ACME requests or asset-file reads. The schema supports explicit PEM certificate/key pairs, ACME, or both; an explicitly selected [dummy certificate](#dummy-tls-for-local-testing) is a separate test-only alternative. The [TLS preparation core](#tls-preparation-core) and [ACME backend](#acme-backend-and-renewal) are integrated into the [joint listener lifecycle](#joint-listener-lifecycle). Schema validation alone does not prove certificate availability or port binding.

## Joint listener lifecycle

All configured SSH and HTTPS TCP inputs are bound before any challenge or application transport is served. A binding failure closes every previously bound input without starting ACME acquisition. Service preparation can already have created SSH keys and other persistent service resources; failure does not delete that state.

The HTTPS listeners then serve only active TLS-ALPN-01 proofs while initial certificate preparation runs. Normal TLS handshakes and SSH serving remain blocked until **every configured domain** has valid material. A failed domain, acquisition timeout, cancellation or unexpected listener exit cancels preparation, removes proofs and closes all inputs. Successfully persisted certificates remain available for the next start.

After readiness, SSH and HTTPS run together, with a caller-owned ACME renewal loop. Unexpected termination of **either** transport stops the whole service; a half-running deployment is not considered successful. Shutdown stops accepting, cancels acquisition/renewal, drains HTTP for at most `gracefulShutdownTimeout` and then closes remaining HTTP connections. SSH retains its separate graceful shutdown and connection-handler cleanup policy. Constructor and configuration loading never start detached ACME work.

The HTTP boundary requires directly terminated TLS, a configured Host consistent with SNI, and matching HTTPS origin (including the effective port) whenever an Origin is supplied. Missing Origin is rejected for non-GET/HEAD methods and upgrades; safe browser navigations may omit it. Cross-site requests into the reserved internal namespace are rejected. Forwarded headers do not override these checks. Absolute-form proxy requests, CONNECT and encoded/dot/backslash path aliases are rejected before routing; no path cleaning can turn them into another flow.

Responses use `frame-ancestors 'none'`, `X-Frame-Options: DENY`, a restrictive same-origin CSP, `no-store`, `nosniff`, HSTS without an implicit subdomain/preload commitment, and same-origin opener/resource policies. There is no CORS grant or cookie-based authentication. HTML documents additionally receive fresh script/style nonces for trusted inline operator HTML and Mantine styles, without unsafe-inline/eval or framing. Authentication, assets and terminal protocols add the limits below.

Before opening TLS or ACME state, runtime paths are canonicalized on a cloned configuration. TLS files/ACME storage are checked against session storage, audit/recording state and static SSH/SFTP inputs. Public asset directories and custom CSS/JS inputs cannot overlap these protected paths; existing hard-link aliases are checked in addition to canonical symlink paths. Public reads additionally enforce rooted containment, stable regular single-link files, size limits and symlink rejection. Disabled HTTP does not inspect its unused paths.

TLS certificate and ACME account/certificate public keys must be distinct from known static SSH keys, audit signing identities, SFTP identities and configured audit encryption recipients, including configured recipients of disabled auditlogs. Copied key material at unrelated paths is not an exemption; audit best-effort policy cannot waive this HTTPS safety check. New ACME keys and cached/renewed certificates are checked before use/publication. Audit decryption private keys are never requested by the HTTPS endpoint.

## Initial discovery and password API

`GET /` and canonical `/<slug>` navigation with HTML Accept serve the built React application when available. Without a built/overlaid index, `/` retains a small static English discovery page. JSON Accept (and non-root requests without HTML Accept) returns discovery/selection metadata, including `requestUser`; these are **not** authorizations. Published links remain host-scoped and configuration-ordered. `HEAD` returns headers only.

The published-slug priority, general/HTTP requirements, host/slug matching, `http.enabled` and `http.requestUser` are enforced by the **same authorizer facade** used for SSH, with an explicit HTTP selection. A published flow's rejected credentials or requirements cannot fall through to another flow. An undiscovered slug retains normal configuration-order matching. Disabled name collection requires an empty `user`; the server never substitutes the principal for `.remote.user`. Discovery cannot predict whether a name, credential or environment will be accepted.

The initial JSON endpoints are:

| Method and path | JSON body | Purpose |
| --- | --- | --- |
| `POST /_bifroest/api/v1/login/password` | `{"slug":"Work","user":"alice","password":"..."}` | Verify through the existing password authorizer and issue a scoped ephemeral permission. All three string fields are required; empty values remain subject to configured authorization. |
| `POST /_bifroest/api/v1/access` | `{"slug":"Work"}` | With `Authorization: Bearer <accessToken>`, recheck the permission, session, identity, target and environment. It does not renew its expiry or touch session last access. |
| `POST /_bifroest/api/v1/logout` | `{"slug":"Work"}` | With the same bearer proof, revoke its browser binding if linked, removing all permissions/children linked to that binding; otherwise remove only this permission and its children. No sibling-binding/grant or SSH disconnect and no session/environment disposal. |

All these requests require the boundary's same HTTPS Origin. Query parameters, unknown/duplicate/null/non-string JSON fields, trailing JSON, encoded request bodies and non-JSON content are rejected. Login bodies are limited to 16 KiB, names to 256 bytes and passwords to 4096 bytes. Internal authentication errors are not returned to the client. Private keys and passphrases are not accepted fields; imported-key support signs locally in tab memory as described below.

A successful login returns `status`, `accessToken`, `expiresAt`, `scope` (canonical HTTPS origin including port and exact slug), the mapped `principal`, `environment` (`terminal` or `management`) and `terminalAvailable` (true for terminal flows, false for Management). The opaque token contains 256 random bits and is indexed by its SHA-256 hash only in server memory. Its permission also pins the verified authorization/flow, session and pure target digest, independently of persistent session ownership. It expires after ten minutes, does not slide and does not survive a service restart. **This is not RememberMe.** The browser client keeps it only in tab memory: never URLs, cookies, LocalStorage or IndexedDB. Possession remains a bearer capability and is not protection against trusted same-origin JavaScript.

Anonymous logins get independent sessions and permissions; the label `anonymous` never merges them. The independent token may authorize a fresh connection only to its own stored session/target. A known session ID, user name or discovery link is never accepted as proof. This does not yet add anonymous web-to-SSH resumption.

There are at most 64 concurrent API requests, four per direct peer IP, 12 login/binding-proof starts (across all methods) and 120 API requests per peer per minute, 1024 tracked peers and 1024 live/retained web permissions. Pending logins, binding proofs and terminals have additional limits below. Forwarded headers cannot change the peer or authority. Limits fail closed with 429 and `Retry-After`; expired inactive entries are reclaimed lazily. Read deadlines bound request bodies to the shorter of 20 seconds and configured `readHeaderTimeout`; non-streaming API writes also have a 20-second deadline. Password/claim requests receive a 20-second cancellation context; multi-step authorizers have the independent lifetime below. Shutdown cancels/drains admissions, including slow body reads/writes, before closing repositories.

Login itself does not provision an environment, renew session access or reserve a connection quota. The connection adapter revalidates permission/target and acquires the same neutral session quota as SSH for **each new execution connection**, including each structured Management operation. It rejects reattachment. Expiry prevents new access but leaves existing authenticated executions alone; an expired permission retained for active children can still prove logout. Explicit logout closes only its own permission/binding's children, while session limits/disposal and session-wide revocation remain stronger controls. Terminal execution, Management metadata, confirmed session actions and client-only artifact verification/decryption are described below.

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

### Browser interactive/device dialogs

The built UI's `Interactive / device login` method now drives Keyboard-Interactive and OIDC Device Flow through this API. Provider info/error text is displayed as plain text and requires acknowledgement, never rendered as HTML or sent to a terminal. Prompt `echo` selects a plain or password field; every response is cleared and belongs to exactly one sequence. Provider-supplied HTTPS verification links require a deliberate click, contain no embedded user credentials and use noopener/noreferrer. There is no iframe, automatic redirect or browser OAuth-token grant.

The tab-only `bwl1.` permission is never exposed in UI state/serialization. The client enforces increasing steps 1–32, 8 KiB/message, 32 KiB total and 4096-byte answers. Pending polls are at least 1250 ms apart; 15-second polls while waiting for user input keep only the existing attempt alive, with the original hard expiry pinned. Poll is a one-time completed-login claim, not a retryable read: lost reply/claim outcomes require a fresh login, without replay or inferred access. Abort/failure only best-effort cancels the logical attempt using an independent bounded request. It never logs out existing grants or disposes a session/workload.

Actual Go HTTPS/Chromium UI tests verify escaped provider markup, echo/secret transitions, interruption after a real final claim, fresh-login recovery, signed local IdP device login without a requesting name, remembered grant reuse and cancellation of a running IdP token request. Public-key/WASM UI coverage is described below; no external IdP or native Local account-policy result is claimed.

### Portable public-key client foundation

The browser client accepts a trusted tab-local key adapter, checks the original `bifroest-http-public-key-v1` challenge against exact origin/port, slug, original user, public key/certificate fingerprint and pinned expiry, and posts only the canonical public key plus one SSH wire signature. A key attempt accepts one proof step with a two-minute cap, never an interactive fallback. Ambiguous replies/final claims are not automatically repeated. The built UI now supplies this adapter through a short-lived Go/WASM worker and the `SSH key login` file/passphrase/certificate form.

The portable `pkg/browserkey` Go core shares server public parsing/challenge encoding/verification and reuses existing SSH import/decryption/signature code. Imports support Ed25519, RSA 2048–8192 and NIST ECDSA, one PEM key up to 64 KiB, passphrases up to 4096 bytes and an optional matching OpenSSH user certificate up to 12 KiB. OpenSSH bcrypt is capped at 64 rounds. Encrypted PKCS#8, PPK, security keys and multi-key files are not supported. The handle can attempt one exact-context proof, including on failure. Import does not establish certificate trust or replace current server policy; no server endpoint accepts private material. Native HTTPS/HTTP2 tests join the SSH session using locally decrypted raw/certificate keys.

The worker receives only transferable tab-memory buffers after runtime readiness, clears temporary bytes, and is terminated after success/error/abort/deadline. Each RPC has a 20-second cap; worker lifetime is at most two minutes. The form resets native inputs and component-local uncontrolled values immediately, retains no primary key/passphrase in application state/IndexedDB/cookies/local storage, and uses unnamed private inputs plus `method=dialog` to prevent a fallback native upload. An explicitly selected empty certificate is a local error, not a raw-key fallback. Only the dedicated worker response permits `wasm-unsafe-eval`; document JavaScript eval/WASM remain forbidden and the worker cannot spawn child workers. No secure-physical-erasure or hardware-binding claim is made.

Actual Go HTTPS/Chromium tests execute all five key algorithms through Go/WASM, verify encrypted/plain imports, wrong-passphrase failure without an authentication request, boot cancellation, valid/expired certificate policy, RememberMe across reload and worker termination before success. The pinned runtime and Go/WASM artifact have public notices/component hashes. The roughly 7.7-MB WASM asset loads only for key import; Go/Node subprocesses are build/test tools, never web actions. Speculative module preloading is disabled to stay within unchanged shared asset/API admission budgets. Browser components now enter the release notices/SBOM pipeline; signed source provenance and other browser/OS runtime coverage remain open.

### Structured Management: bounded read-only metadata

An authenticated Management environment now provides structured flow summaries and session list/detail tables, without another administrator login, terminal commands, CLI parsing or SSH tunneling. The fixed POST routes are `/_bifroest/api/v1/management/flows/list`, `management/sessions/list` and `management/sessions/show` under the same API prefix. Every request carries the exact `slug` and existing `bwa1.` Authorization proof behind the unchanged TLS/Origin boundary; cookies and selectors alone grant nothing. There are no query credentials, dynamic command/argument fields, redirects or automatic retries.

List fields are canonical string `limit` (1–20, default 20) and `after`; sessions also accept `flow`, original requesting `user` and `state` (`active` by default, or `all`/`new`/`authorized`/`disposed`). Details require exact `flow` and session `id`. Versioned JSON responses are bounded to 64 KiB. Cursors are bounded canonical selectors bound to operation/filters, never authentication or a stable snapshot. Each real operation acquires a new shared session lease, inherits current authorization/identity/target checks and shutdown/logout/revocation cancellation, and runs the common session activation/activity/task audit/recording/sealing/final-audit lifecycle. Buffered data is published only after those configured policies succeed. Read-only refers to the operation on inspected targets, not a promise to avoid the caller's normal session activity/audit updates.

The CLI and HTTP share Go data-view builders. Original `user`/`remote` are not shown as verified identity. Stored association issuer/subject are reported separately when available; missing legacy/anonymous evidence never invents a principal. Damaged entries are skipped with a visible partial-data count, without private diagnostics or destructive repair. Metadata endpoints accept no credential-detail/artifact or client policy flags; session mutations use the separate confirmation protocol below. Conservative forced-read and exact single-session action ceilings are supported as described next; other forced commands remain denied, with SSH behavior unchanged.

Actual HTTPS/Chromium tests cover pagination, session tables/details and actor-changing reauthentication with cleared results while the CLI application is unavailable. Protocol tests additionally cover bounded selectors, shared quotas, cancellation/own logout/global revocation, sibling-grant preservation, strict final-audit refusal and damaged-state preservation. Typed original-artifact routes and the separate client-only evidence view are described below.

The additional fixed `management/auditlogs/list` and `management/recordings/list`
POSTs provide artifact catalogs under the same metadata authorization and driver,
not the content-transfer permission. Both accept string `limit`/`after`; recordings
also require `auditlog`. The same 20-entry/64-KiB bounds apply. Cursors bind operation
and filters; recording cursors bind auditlog and canonical recording ID. Selectors
grant no permission, snapshot consistency or freshness. A configured `audit ls`
ceiling permits the equivalent auditlog summaries only; all forced recording
enumeration and other cross-operation requests remain denied.
`includingCredentials` does not add fields to these fixed DTOs.

Auditlog rows contain only name/enabled/recording-enabled/encryption-configured
metadata, including disabled configurations. Recording rows reuse the existing Go
`RecordingView`, native sealed page inventory and inspection/close paths. Native
1000-row limits and evidence formats, including encrypted `becast-cbor/v1`, remain
unchanged. One lookahead ID determines `next` without inspecting its content; every
selected recording must pass the existing server inspection and cleanup before the
page can be published. Corrupt selected evidence fails the entire page, with no
partial JSON/private diagnostics or repair. Read quotas, cancellation and final
audit/sealing remain mandatory. Recording pages also share the existing bounded
heavy-operation start budget because inspecting signed artifacts can be expensive.

The catalog is **server-reported metadata**, not independent browser evidence.
Its `verificationScope`, producer and recipient claims never seed client trust.
Choosing a row fills only download selectors and resets old local evidence/pins;
it does not download, verify or decrypt automatically. The view clears actor-owned
pages on authentication changes/logout and refuses late replies after cancellation.

### Browser workspace

The browser workspace separates **Sessions**, **Recordings & audit** and
**Server**. Switching existing views does not list, download, verify, execute
or mutate anything automatically. The navigation stays in this tab; it does not
create another login, role or authorization policy. Actor changes clear the
previous actor's results, while switching views within one actor retains local
results. A commit or unknown session-action outcome cannot be dismissed by
switching views. The exact-ID action entry is a separate expandable path for
credentials without list/show rights; normal session actions remain at the
selected session. Narrow screens use session cards with the same permitted
metadata instead of a table extending beyond the viewport.

Recordings follow explicit selection/download, local verification and result
steps. **Open content, prepare playback or export** explicitly selects full
private verification and preparation of a local export; it does not save or play
automatically. Signature-only checking remains the default, and advanced options
retain independent verification-depth/export/redaction controls. No workflow
choice adopts server-supplied producer/recipient hints as trusted expectations.
The terminal fills the viewport below a compact status/tab bar. Sign-in,
reauthentication, appearance and account details use dialogs. A confirmed
terminal-capable sign-in or explicit RememberMe resume opens one new shell tab
automatically. **+ / New terminal** opens another fresh shell with the current
grant; selecting an existing tab never opens or reattaches a connection. There
is no command/exec or PTY-toggle form in the UI; the existing wire protocol still
supports these operations for other clients. The UI requests a shell with PTY
and does not silently retry without PTY if the current key/environment denies it.

Each in-page tab retains its own immutable access/actor, xterm, output and socket.
Reauthentication opens a new tab without reassigning the old execution. Closing
a live tab asks for confirmation and disconnects only that execution, never
disposing its session/workload or another tab. Completed output remains until
the user closes that tab. There are at most eight tabs per window as a local
resource bound, independently of all server connection/admission quotas. Pending
initialization is retired on cancellation/logout; uncertain authentication or
RememberMe enrollment does not open a shell. Expiry does not terminate existing
executions, and failed/dropped shells are never automatically retried. Reload
loses the in-memory tabs: a subsequent confirmed login starts a fresh execution,
not a reattachment.

With an expired grant, **New terminal** asks for a fresh sign-in before opening
another connection; closing the dialog leaves the old shells usable. Rejected or
canceled reauthentication also preserves existing tabs and their original grant,
without forwarding dialog input into those terminal streams. A lost logout reply
keeps local access blocked and does not claim successful logout or process exit.
No automatic retry occurs. **Retry logout** is explicit; denial of that request
does not itself prove server revocation or unblock local access.

### Conservative ForcedCommand operation equivalence

`POST /_bifroest/api/v1/management/version/show` is an explicit Management metadata
read, with optional string `long: "true"` (default) or `long: "false"`. The fixed
response adds `versionInfo: { detail, text }` to the versioned `version.show`
envelope. Text comes from the same native `sys.FormatVersion` core as SSH, including
its line framing; it is server-reported build metadata, not an independent source,
runtime or signature attestation. The UI renders text only and clears it on actor
change/logout. No CLI parser, subprocess, command/argument field, artifact request
or new role is involved; normal read quotas, audit/recording and final-audit success
remain mandatory before delivery.

The operator-configured forms `version`, `version --long`, `version --long=true`
and `version --long=false` permit only this operation and their exact long/short
mode. In particular, a forced short version cannot expose vendor/Go/features via
the long selector. Other operations, artifact transfers and mutations remain denied
even if the environment enables transfer/credential inspection. Duplicate flags,
unknown spellings/options and command chains remain rejected. Native SSH/HTTP
reference tests compare exact bytes for all four accepted forms; actual HTTPS/
key-WASM/Chromium tests exercise explicit selection, denial of long/cross-operation
reads, plain-text rendering, CSP and logout cleanup without the CLI application.

The other supported read forms are `flow ls`, `audit ls`, `session ls` and `session show <canonical UUID>`, each mapped to the corresponding typed read. Supported unique flags are `--format` (`table`/`json`/`yaml`/`cbor`) and, for session lists, the existing `--flow`/`--user`/`--state` filters. SSH-compatible POSIX token splitting accepts quoted values and `--flag=value`/`--flag value`; no browser-supplied command enters this parser. Unknown/duplicate options, file/config expansion, aliases, shell operators/command chains, malformed values and wire/dispatcher names remain fail-closed. This subset does not claim every spelling accepted by the CLI.

Requested filters are intersected with forced filters, including `active` as the forced list default. Paging or requesting `all`, another flow/user, a show or a mutation cannot widen that operation's authority. A fixed show retains its exact UUID and the CLI's global ambiguity refusal, even when HTTP supplies a flow. Forced session responses never add association issuer/subject. Table lists omit remote/last-access/valid-until metadata; other recognized formats/show retain only their existing base fields. Table/CBOR timestamps are second-precision as over SSH. `policyLimited: true` marks policy withholding explicitly, not missing ownership or an infinite lifetime; the UI labels it accordingly. Unrestricted reads remain unchanged and forced reads are audited as forced tasks.

Real SSH/HTTP reference tests exercise all four formats and the forced override of a different client command. API tests verify filter intersections/defaults, paging, exact-ID/global ambiguity and blocked cross-operation/mutation access; actual HTTPS/Chromium signs in via Go/WASM with a forced key and verifies field withholding/denied access. Other operations and dispatcher equivalence remain incomplete. Keep using their existing SSH restrictions rather than removing them.

The action-only forms `session disconnect <canonical UUID>` and
`session dispose <canonical UUID>` permit only that exact action and ID, with an
optional unique `--format` in the same four formats. HTTP's required flow selector
does not bypass the CLI's global duplicate-ID refusal: preparation and commit both
check current uniqueness, including immediately after the action-started audit.
These forms grant no list/show/version/catalog/transfer capability. Use **Action on
a known session** to enter an already known flow/ID without a preliminary read.
The preparation uses the shared execution/audit/recording driver but never invokes
`session show`; its target contains only `flow` and `id`, with no owner, state,
requester, remote, creation/activity/expiry data or generation digest. All normal
one-time confirmation, self-protection and unknown-outcome rules below still apply.

For `audit ls`, all four SSH formats already expose exactly name/audit-enabled/
recording-enabled/encryption-configured. The typed response reuses this exact
summary, including disabled configurations; paging only partitions the same
name-ordered list. It adds no settings, paths, credentials, event/producer/recipient
details or new policy marker for fields that were never withheld. The same quota,
20-entry/64-KiB response, cancellation, recording seal and final-audit checks apply.
Other metadata, session actions, recording enumeration and artifact transfers
remain denied even with `allowArtifactTransfer: true`; catalog selection is not
permission or an automatic download. Native SSH/HTTP comparisons and real HTTPS/
Go-WASM-key/Chromium tests exercise these boundaries and 20+2 summary pages.

An extra `active` filter is allowed only when the forced list already selects `active`. This predicate also tests exact validity, not just the visible state; otherwise row presence could reveal a withheld or finer-grained deadline. For other forced states choose `all` or a normal state (`new`/`authorized`/`disposed`) explicitly, rather than the UI's initial `active` filter. Tests cover this refusal in every output format.

The existing Go management framing has also been extracted into portable Reader/Writer decoders, reused by the native client and tested as actual Go/WASM under the MISE-selected Node runtime. Audit transfer storage is a separate provisional sink, with the complete bounded header checked before writes and digest/end/count/EOF checks retained. A transfer digest or declared producer is never a signature/trust/decryption result; successful transport completion and independent full evidence verification are still required. Separate transport/evidence workers and the artifact view below preserve that boundary.

The shared Go response receiver requires final transport success as well as decoding. It owns abort/join/close without retrying or undoing the operation, and returns no typed result on transport failure, cancellation or cleanup error. Streaming bytes remain provisional. Native SSH uses its actual exit status and diagnostic drain; malformed data or missing exit status cannot complete the result. These lifecycle tests also run as actual Go/WASM under Node, not as browser downloads. The typed HTTP artifact adapter below signals success only after the shared task's recording seal/final audit, never from body EOF alone.

### Typed original-artifact streaming

The fixed POSTs `/_bifroest/api/v1/management/artifacts/recording` (`slug`, `auditlog`, canonical `id`) and `/_bifroest/api/v1/management/artifacts/audit` (`slug`, `auditlog`) require the existing scoped bearer and a Management environment with `allowArtifactTransfer: true`. `includingCredentials` does not enable transfers; neither policy flag, a command, path or decryption key is accepted from the client. All forced-command credentials remain denied here. Existing direct TLS/Host/SNI/Origin/peer rules, admission/start budgets, quotas and the twenty-second request deadline remain unchanged.

Each operation uses the common registered lease/task/environment/audit/recording/sealing/final-audit driver and the same original sealed-recording or signed live-audit-snapshot writer as SSH. No SSH-shaped task, CLI parser, second login, new role or server-side decryption is involved. Own logout closes its own children, not sibling grants or the session/workload. Audit snapshots remain point-in-time signed checkpoints, not a claim to contain the transfer's own later final audit.

`application/vnd.bifroest.management-transfer.v1` responses carry a fixed magic, bounded data frames (at most 32 KiB each), a data-end marker and a separate canonical completion (at most 4096 bytes). Only after successful recording seal/final audit and access checks does the server append completion binding the exact operation/auditlog/ID, byte count and SHA-256, then end the HTTP body. Data-end and even HTTP 200/EOF alone are not success. Failures after streaming begins omit completion rather than appending private diagnostics. Original evidence formats stay unchanged; data totals retain the native 32-GiB recording/1-GiB audit limits plus bounded headers, without whole-artifact buffering or relaxed timeouts.

The portable Go HTTP response adapter validates status/media/encoding and implements separate Read/Complete/Abort/Close over caller-owned provisional staging. Request opening must still enforce same-origin TLS/scope/bearer, omitted cookies and redirect refusal. Completion proves transport/task success, **not** artifact signatures, producer trust or decryption; independent full evidence verification requires immutable client inputs and separately trusted expectations.

The existing full Recording verifier is shared by native callers and portable `pkg/recording/cast`: Cast/v3 signatures/semantics and clear/encrypted native bcast/becast envelopes, age authentication, bounded Zstd/CBOR chunks, reconstructed Cast, counts/digests and exact immutable ReaderAt passes. Export emits nothing before full verification, then requires the same immutable input and caller-owned atomic output staging. Outer-only authentication or an incremental renderer is not full verification. Separately expected producer trust remains mandatory unless untrusted verification is explicitly requested; header/transport assertions never become trust anchors. Frozen native vectors run as actual Go/WASM under MISE/Node, including decryption and byte-identical exports. Audit uses the shared immutable segment/producer-snapshot verifier; native real-file identity/link/tree proofs stay in native adapters, not synthetic browser filesystem stubs.

Actual HTTPS/HTTP2 tests transfer clear/encrypted artifacts with the CLI application absent and independently verify signatures/checkpoints. They block final audit after the client sees data-end, inject final-audit or seal failure, and revoke/logout/cancel at that boundary: none can return a successful header prematurely. Protocol/Go-WASM tests separately cover bounds, selector/count/hash/canonical-envelope checks, trailing/physical-EOF failure and body ownership. Actual HTTPS/Chromium additionally exercises the artifact view below.

### Browser artifact verification and decryption

The Management view accepts a catalog selection or an exact auditlog/recording ID.
Downloads stage only tab memory, at
most 64 MiB payload / 72 MiB framed response; larger artifacts require native tools.
One short-lived bearer-free Go/WASM transport worker checks completed framing and
real EOF. Its immutable Blobs remain explicitly **evidence-unverified**.

Verification is a separate explicit action in a second short-lived Go/WASM worker.
Provide independently trusted producer/recipient expectations and choose expected
encryption, outer/full-private depth and complete/captured-prefix audit scope.
Server hints never populate these fields; selecting another artifact resets them.
An omitted producer pin requires explicit untrusted mode. Signing trust, validation,
decryption, scope, bytes-only provenance and absent freshness remain distinct in
the result. Complete supplied evidence does not prove that newer records were not
withheld, and same-server code is not an independent offline verification environment.

For encrypted private verification, select a local Ed25519/RSA PEM/OpenSSH recipient
key (maximum 64 KiB) and optional passphrase (maximum 4096 bytes; bounded bcrypt).
Those inputs have no upload fields or POST fallback and clear on submit/change/cancel.
Private values and plaintext never go to the server or browser persistence. Worker
lifetime is bounded to two minutes; its compressed WASM has an 8-MiB compressed /
24-MiB decompressed loading bound without changing document CSP or the general
asset limit. No physical secure-erasure guarantee is made for browser memory.

Only full private success may prepare a bounded Cast/JSONL export. Audit export is
redacted unless sensitive fields are explicitly requested, independently of private
validation. Saving an export or an explicitly unverified original requires another
click. Owned Blob URLs and previous results are retired on option/actor changes,
discard, cancellation or logout; previously saved files cannot be removed by clearing
the view, and a save request does not confirm a successful filesystem write.

### Local read-only recording playback

Full private verification plus an explicitly prepared Cast export enables a
separate local player, never an execution connection. Preparation and Play are
separate user actions. A fresh existing Go/WASM evidence worker receives only the
immutable local Blob and independent recording-ID/producer expectations, not a
bearer, URL, key or server action. The shared Cast verifier's provisional event
visitor stages exact output bytes/stream order/resize/timing; only final signature,
real EOF and complete checks release a bounded rendering image. Server metadata
never supplies trust pins. Outer/decryption/source/freshness evidence stays in the
preceding result; rechecking the Cast does not manufacture those proofs.

Local input/plan is bounded to 64 MiB, 100,000 events, 512 columns/256 rows and
32,768 cells. Larger valid recordings are explicitly refused without changing
native limits. A read-only xterm with bounded scrollback ignores clipboard/title/
window/link host actions and has no stdin, socket, command, EOF or signal channel.
Play/pause, 0.25–8x speed, joined reset and discard are local; browser timer precision
is approximate. At most one bounded write is in flight, with a drain deadline;
rendering failure is never successful playback. Recorded outcome/exit status is
not a new live exit result. Expectation/source/actor changes and logout/cancel
retire private images, workers, timers and viewport; no plaintext is uploaded or
persisted, and no physical memory-erasure guarantee is made.

### One-time confirmation for session disconnect/dispose

From a selected session detail or an explicitly entered known target, the browser first calls `management/sessions/prepare` with exact `flow`, `id`, `action` (`disconnect` or `dispose`) and `slug`. This audited/recorded preparation has no target side effect and grants no implicit read. A self-target or unavailable target is rejected. The reply's `target` always contains `flow` and `id`; unrestricted access additionally receives a `details` session item, while action-only forced credentials receive neither details nor fabricated empty/unknown metadata. The server pins the generation internally and gives a fixed one-minute, 256-bit, hash-indexed memory-only `bmc1.` permission bound to the exact original access grant, origin/slug/direct peer/action and immutable target creation/association evidence. At most 64 preparations/four per peer are retained under existing request/start budgets; a winning in-flight claim retains its slot until it returns.

`management/sessions/confirm` and `cancel` accept only `slug` and `confirmationToken` plus the original access Authorization bearer. No URL/cookie or replacement target/action is accepted. Confirm consumes once before any possible effect, including errors. Target generation is checked before use and again after the started-action audit; a stale/replaced target is refused. This is not protection against a privileged operator changing protected filesystem state concurrently with the final backend operation. Unused cancellation only retires a preparation; it is never logout, disposal or undo.

The shared SSH session-control core enforces caller self-protection and cross-flow action audit. Disconnect closes the current registry snapshot without revocation/workload disposal, so a new connection can use the same session. Dispose revokes and closes connections, stops refresh, durably disposes before cleanup, then uses the normal environment/authorization lifecycle. Partial/final-audit failure may already have taken effect. Both typed actions still run the common quota/activation/task audit/recording/sealing/final-audit execution driver, without CLI parsing or a new role model.

The dialog holds one opaque handle and the original actor, displays the exact target (and fresh owner/creation metadata only when permitted) and requires the exact typed `flow/session ID`. Any ambiguous commit response is outcome-unknown: no replay, success or rollback is inferred. Stop-waiting cannot undo an action. Explicit reads remain available only within the original read policy; reauthentication/logout are locked during commit/unknown outcome until success or explicit dismissal of the local warning. Actual Go HTTPS/Chromium tests prove unused cancel, two live executions being disconnected, a fresh execution in the same session, disposal with a lost success response, revoked-state inspection and no automatic retry. The same browser tests with action-only Go/WASM keys prove confirmation without hidden inspection requests or extra session metadata. Native tests cover one-shot races, scope/peer/parent-grant binding, self-protection, expiry, target replacement and final-audit failure after mutation.

## WebSocket terminal protocol

`GET /_bifroest/api/v1/terminal` accepts an HTTP/1.1 WebSocket upgrade with exactly the subprotocol `bifroest-terminal.v1`. Ordinary APIs continue to support HTTP/2; extended CONNECT/HTTP2 WebSockets are not implemented. The normal direct-TLS/Host/SNI/same-HTTPS-Origin boundary runs before upgrading. Query parameters and upgrade request bodies are forbidden. No compression is negotiated.

Browser WebSocket APIs cannot supply an ordinary Authorization header. The access proof is therefore sent only in the **first text message**, within five seconds of upgrade, never in the URL, cookies or subprotocol:

```json
{"type":"open","slug":"Work","accessToken":"bwa1.…","task":"shell","pty":{"term":"xterm-256color","columns":80,"rows":24},"environment":["LANG=en_US.UTF-8"]}
```

For exec, use `"task":"exec","command":"..."` instead; shell requests must omit `command`. `pty` and `environment` are optional. The empty slug selects the root. No client-selected session/connection ID, subsystem, private key or passphrase is accepted. Objects have exact case-sensitive field sets: unknown/duplicate/null fields, non-UTF8 controls and trailing JSON fail closed. Commands are limited to 4096 bytes without NUL. Terminal names are 1–128 ASCII letters/digits or `-_.+`; columns/rows must be positive uint16 values and optional `widthPixels`/`heightPixels` uint32 values. At most 32 environment strings are accepted, each `NAME=value`, with ASCII identifier names of at most 128 bytes, values of at most 2048 bytes, 8 KiB total and no NUL or case-insensitive duplicate names. Existing server/key/client environment-layer and forced-command policies still decide the effective environment/command.

The server rechecks the scoped proof, authorization, session, identity, effective target and environment before acquiring a fresh shared connection quota. It replies `{"type":"ready","connectionId":"..."}` after registration, **not** as a promise that provisioning or execution will succeed. Each socket owns exactly one new shell/exec, with the shared task/audit/recording driver; reconnect or reload never reattaches to an old execution. Management flows are rejected here, not routed through CLI subprocesses or SSH tunnels; they use the separate structured HTTP interface.

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

Tests use real HTTPS/WebSocket connections and signed filesystem recordings for raw stdin/stdout/stderr, EOF, resize/signal capture, separate executions in one session, strict recording failure, redacted backend errors, proof/Origin/query rejection, quotas, expiry/logout/revocation, oversized/fragmented floods, bounded queues, slow-reader write timeout, missing Pong, abandoned open and shutdown. The initial real SSH/two-WebSocket shared-session fixture uses the built-in Dummy backend; that fixture alone is not browser UI or container runtime evidence.

The separate opt-in `TestOpenSSHKubernetesBrowserSharedWorkload` starts an owned
kind cluster through the existing E2E harness, with its own kubeconfig and no use
of the operator's current cluster. On Linux with rootless Podman it drives real
OpenSSH and the actual HTTPS/key-WASM/xterm UI against one Kubernetes Pod. It checks
the same persistent session, Pod UID, effective UID and shared marker state, but
four distinct connections across browser reload/explicit reauthentication/logout
and subsequent SSH. All four signed recordings and task/audit correlations are
verified after shutdown. The container acquisition lease preserves the backend's
neutral execution capability without SSH task stubs or extra quota references.
This is not Docker-engine, Windows/ConPTY or macOS runtime evidence. See
[`web/README.md`](https://github.com/engity-com/bifroest/blob/main/web/README.md)
for prerequisites and the explicit browser E2E invocation.

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
:   Optional complete per-file filesystem-before-embedded overlay, including `index.html`, images and hashed bundles. An empty value selects only built embedded assets. Only absence permits fallback; an existing unsafe/unreadable resource fails closed. API/WebSocket paths are never mapped through this directory. The opened root stays anchored until restart; individual file updates are visible, replacing the root directory requires restarting. See [browser resources](#browser-resources-and-customization).

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

Tests include actual TLS, HTTP/2 and TLS-ALPN proof handshakes, private CA and IP cases, joint SSH/HTTPS startup/failure/cancellation, bounded HTTP shutdown, and path/key separation. ACME tests exercise issuance, persistent account/certificate storage and renewal against a local test CA through a real HTTPS listener; no public CA is contacted. The authentication APIs and incremental password/RememberMe UI have additional coverage below.

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
:   Positive **sliding unused timeout** for explicitly opted-in browser bindings. Successful fresh possession proof, current authorization and audit checks extend it. Expiry requires regular login again; it does not terminate already authenticated connections, dispose sessions/containers, or override shorter session limits and revocations. This setting alone does not enroll a browser; enrollment/recovery use the explicit UI actions below.

### Enrollment, resumption and revocation protocol

These server APIs, the encrypted IndexedDB/password/RememberMe client core and the explicit opt-in/recovery UI are implemented. Enabling HTTP, regular login or configuring `rememberMe.idleTimeout` does not silently enroll a browser. The checkbox starts unchecked; independent non-exportable signing/encryption keys are created only after opt-in. Imported primary private keys/passphrases remain exclusively in the current tab through the local key-import UI described above.

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

Simple, htpasswd, OIDC-device and None authorizers support their applicable primary methods; Bifröst delegation requires its exact currently valid certificate. Local key/certificate bindings retain their current-key/certificate policy checks. **Local password/keyboard-interactive enrollment and resume are supported for Linux's repository backend with empty `pamService`**, using the explicit native account-policy checker. PAM-backed and Windows SAM password resumption still fail closed until their separate native adapters are available. Regular primary login is unchanged. Third-party authorizers require an explicit trusted `SessionResumer` capability; diagnostic `RestoreFromSession` or a name/UID/SID lookup alone does not opt them in.

Repository-backed Local resumption reads only the stored name/UID selector and
fresh native account data, not historical environment or key/rights snapshots.
The corresponding current password/interactive permission and empty-password
policy are evaluated with current identity/groups. Independent readonly snapshots
before and after policy/environment validation reject account locks, expiry or
required password changes, name/UID replacement, ambiguous/malformed records and
unavailable/changed files. Group membership must be fully decodable rather than
silently dropping malformed groups. File locks and special-file opens are nonblocking;
each passwd/group/shadow file is bounded to 16 MiB and 100000 entries. Failure
does not create/modify account files, repair retained session tokens or advance a
binding's usage/revision. This rechecks eligibility for a new grant; it does not
claim instantaneous revocation of already authenticated children when an external
account file changes. Explicit logout and session-wide revocation retain their
existing stronger controls.

Linux tests use owned passwd/group/shadow fixtures through real TLS/HTTP2 and
WebSockets, with independent binding signatures, lock-after-challenge refusal,
unchanged rejected bindings, service restart and logout without disposal. Real
Chromium UI tests separately cover password and keyboard-interactive opt-in,
browser-profile restart/resumption, uncertain enrollment recovery and CSP. No
host account is created and no PAM/macOS/Windows logon-policy result is inferred.

Successful `revoke` returns 204 after durable binding removal and closes all linked web permissions/terminal children, never sibling bindings/grants or SSH connections. Ordinary `logout` has the same binding-scoped effect for an enrolled/resumed permission, and remains permission-scoped without a binding. Persistence failure is reported as 503, not acknowledged as durable logout; linked in-memory access is still closed. Binding expiry only denies future resumption, without terminating authenticated grants/connections or disposing the shared session/container. Session validity and session-wide revocation remain stronger controls.

Tests cover explicit proof-before-enrollment, replay/scope/peer/revision isolation, current selection/requirements/key/certificate restrictions, strict audit failures, shortened idle-policy expiry without revival, linked/sibling logout, failed durable logout, anonymous isolation and service restart with new ephemeral access. Real HTTPS/WebSocket tests execute with a resumed permission and revoke its children. A local TLS IdP verifies retained refresh rotation and access-loss rejection. These are server/protocol tests, not an IndexedDB, native Local account-policy or browser UI/shared-container E2E result.

### Binding storage and possession-proof core

The optional trusted `session.BrowserBindingSession` capability stores browser permissions separately from SSH remembered keys. The FS implementation uses the private `wb` session sidecar with schema `bifroest-browser-bindings-v1`. A record pins canonical HTTPS origin/effective port, exact slug, original possibly empty requesting name, normalized identity, effective target digest, a browser-generated P-256 **public** key and server-verified primary credential provenance (authorizer kind, method and, for key login, the exact public key/certificate). No primary secret or rights snapshot is persisted. Foundation-era records without credential provenance remain inspectable/revocable but cannot resume. The containing path supplies flow and session, and the file envelope must repeat those exact identifiers: copying a sidecar to another session/flow cannot transfer it. The random 256-bit `bbr1.` identifier is only a selector, not a bearer credential or proof of ownership. Anonymous bindings remain local to their own session and do not create shared anonymous associations.

Creation and use require a trusted post-verification caller. The storage API itself does not authenticate a browser or replace the authorizer/service boundary above. A separate eligibility check does not renew the binding or advance its revision, but persists an observed shorter-policy expiry even when an HTTP proof start is rejected before authentication. Binding/claim processing neither selects a sibling session nor allocates a replacement one.

The FS store checks the current session's expiry/disposal under the same repository lock as the binding update. Each successful use atomically advances a persisted revision and sets a new unused deadline; stale concurrent uses cannot both win. The effective eligibility deadline is the earlier of the persisted expiry and `lastUsedAt + currentIdleTimeout`, so shortening the configuration takes effect and increasing it cannot revive an already expired permission. Waiting for the repository lock cannot backdate a use. Creation can reclaim expired binding capacity. There are at most 16 records per session and 128 KiB of sidecar state; exact JSON parsing rejects duplicate, unknown, null, mistyped, malformed Unicode and trailing data. Reads require a stable, private, service-owned single-link regular file. Writes use protected temporary files and atomic replacement. Malformed/insecure state is not repaired or overwritten, and binding state protects broken session metadata from destructive automatic cleanup.

Binding creation, inspection, successful use, expiry and storage revocation never touch session last access, alter authorization/environment tokens, allocate/release execution quota, register an SSH remembered key, close existing connections or dispose a session/workload. Storage revocation removes only that binding; the HTTP layer additionally closes its linked web access as described above. Authorizer revalidation may independently refresh OIDC credentials under its existing policy. Audit events use the distinct `browser-remember-me` authentication method without changing artifact or evidence wire schemas.

The standard-library-only `pkg/browserauth` core supports independent browser-generated ECDSA P-256 keys: canonical standard Base64 of WebCrypto's 65-byte uncompressed public point, and fixed 64-byte IEEE-P1363 `r || s` signatures using ECDSA/SHA-256. Challenges have a `bifroest-browser-remember-v1` zero-terminated domain prefix followed by server JSON binding purpose (`enroll`, `resume` or `revoke`), origin/slug, flow/session, target, exact public key, fresh 256-bit nonce and a one-minute expiry. Existing-binding challenges also pin binding ID and revision; enrollment has neither yet. Sign the exact supplied bytes, never reconstructed JSON. Each in-memory challenge accepts at most one verification attempt, including failed/expired signatures. Neither an SSH signature nor a certificate CA signature is a browser RememberMe proof.

Tests cover restart persistence, atomic concurrent use/revocation, sliding and shortened idle deadlines, stale/expired use, session limits/disposal, anonymous isolation, unchanged session/tokens/quotas/SSH keys, bounded/strict/private storage and preservation during cleanup. An optional native Node/WebCrypto interoperability test generates separate non-exportable signing and AES-GCM keys, checks export denial and verifies its actual P-256 possession signature in Go (`BIFROEST_TEST_NODE` selects a required runtime). The core also cross-compiles for JS/WASM. This storage/proof test layer alone is not a browser-profile protection guarantee. The connected core and opt-in UI have additional native tests below; non-PAM Local account-policy coverage is described above, not inferred from this portable proof layer.

### Browser client core and first opt-in UI

The TypeScript core under `web/` now implements explicit opt-in at its API boundary, independent non-exportable P-256 signing and AES-GCM encryption keys, and real IndexedDB structured-clone persistence. It stores keys before an enrollment request could create a server binding. Only the public origin/slug hash and a random local generation ID are plaintext record selectors; flow/session/binding metadata is encrypted with fresh AES-GCM IVs and authenticated record context. Primary secrets, ephemeral access/attempt tokens and authorization snapshots are not accepted metadata fields. Missing keys or corrupt/unsupported storage require regular login; there is no private-key export/import or memory-only persistence fallback.

Local generation compare-and-swap prevents concurrent enrollments/completions and stale deletion from replacing another tab's record. Pending records can sign enrollment only; completed records sign resume/revoke only after checking the exact challenge domain, purpose, scope, public key and binding, using the original supplied bytes. Local deletion alone is **not** server logout/revocation and must not be presented as such.

An actual headless Chromium suite checks non-exportability/export denial, encrypted records, scope/proof isolation, concurrent updates, corruption and unsupported storage. A separate owned temporary browser profile survives an actual browser-process restart; the restarted client signs a challenge supplied and verified by the Go `browserauth` core. These tests use a secure-context loopback HTTP fixture, not production HTTPS/authentication. They do not establish Windows/macOS profile protection, hardware binding, other browser-engine support, or login/UI E2E coverage. The native Go subprocess is a test helper only, never part of a web action.

The `BrowserClient` HTTP adapter now connects regular password login and the RememberMe protocol to this storage core. Access objects retain their bearer privately in tab memory and serialize only display metadata. Enrollment is a separate explicitly opted-in operation; failure does not automatically revoke a successful primary login. Fetch uses `credentials: "omit"`, `mode: "same-origin"`, no-store, no redirects, header-only proofs, a 20-second request budget and a 64-KiB response limit. POSTs are never automatically retried and private diagnostics are not returned to UI callers.

Before proof submission, failed enrollment may remove only its own newly created pending record. Once a claim may have committed, missing/malformed responses or a failed encrypted local completion remain `outcome-unknown`; keep the key, do not replay the claim or automatically log out sibling grants. An explicit logout can reconcile through the original parent permission's server binding link, including during a late enrollment. A pruned token can instead freshly prove only that access's own known binding; an unrelated regular login must not adopt a different actor's saved record. Proof-based forget deletes local state only after successful remote revoke. Failed durable logout/revoke preserves state for retry; CAS preserves another tab's newer generation. Existing saved registrations are not silently replaced or revoked after regular login.

Real Chromium tests cover these HTTP state transitions, cancellation/late replies, lost responses, failed completion/logout, stale deletion, scope and bounded/redirected replies. An additional explicitly requested Go test serves the actual built client through an owned HTTPS fixture: password login, enrollment, browser-process restart, same-session resume, neutral WebSocket execution and binding logout/revoke all use the real Go HTTP authorizer/session boundary. Independent primary access survives. Cookie-free HTTP API requests, rejected cookie-only WebSockets and same-origin rejection before a foreign destination are verified. This is not React UI, real shared-container or native Local password-policy coverage. Test-only asset routes do not provide production asset serving.

The React 19/Mantine 9 UI uses the same client, en-US message keys and memory-only auto/light/dark appearance. Passwords are not retained in application state, access tokens never enter rendered metadata, and disabled requesting-name collection omits the input and sends an empty name. A successful primary login remains known when RememberMe cannot be confirmed, but uncertain enrollment blocks new automatic shells until reconciliation. Unknown enrollment and unconfirmed logout remain visibly distinct from success; failed logout blocks new local actions while retaining the owned capability for retry. Remote revocation and explicit local-only removal have separate confirmation dialogs. A dialog retains its selected key/record, so another tab's replacement is not silently adopted. Native UI tests cover actual Go HTTPS, browser restart, unchecked opt-in, interrupted claims, local-only recovery, name-free input, customization, theme changes and CSP enforcement. The authentication API alone does not provision a workload or acquire an execution lease; after a confirmed terminal-capable login the built UI separately opens one fresh shell connection.

Vite 8/Oxc/Rolldown builds the app and dependency-free HTTP client core without Webpack/Babel. App preparation builds the portable Go/WASM components and validates their pinned runtime. The Management panel loads only for an authenticated Management environment. Node/browser automation and Go build subprocesses are build/test-only. Release builds require frontend preparation and its exact asset/input inventory before Go compilation; an unbuilt source-only checkout using direct `go build` remains API/SSH-capable. Forced-command equivalence, signed source provenance and additional browser/OS runtime coverage remain incomplete. See `web/README.md` for development, an explicit non-release runtime-file override and opt-in native tests.

### Owned xterm shell tabs

The terminal-capable UI opens one shell after confirmed login and offers additional shells through the tab bar. Each uses PTY, keyboard/binary input and resize; input EOF and INT/TERM requests remain explicit actions in the active tab's menu. Each tab is a fresh shared-driver execution, not reattachment. There is no separate command-execution form, automatic reconnect or CLI-based Management workaround. The first open frame alone carries the tab-memory proof. Connected denotes connection registration, not a provisioning guarantee; a clean/abnormal close without a validated exit remains unknown, not status zero. Final renderer jobs drain before publishing an exit status.

Client buffering per shell is bounded: 64 KiB queued stdin, conservative pacing below server byte/message/control budgets, 16 queued controls, native send-buffer backpressure checks, 64 output jobs/256 KiB and five-second render/write budgets. An oversized or stalled queue closes explicitly rather than silently truncating/replaying input. Scrollback is 1000 lines per tab, with at most eight tabs per window. Timers/resize observers/callbacks are drained or detached on cleanup; each tab has its own renderer and immutable actor instead of resetting and reusing another execution's output. Hidden tabs keep their own output and are refitted when selected. Only the active tab accepts input; authentication/account/confirmation dialogs disable terminal input and cannot have focus stolen by a late connection callback. Remote clipboard, window/title control and URL activation are not enabled. Theme follows the computed UI theme. New-access expiry or a deliberate fresh login does not replace an existing execution; its actor-at-start remains displayed independently of the current login.

The locked xterm 6.0.0 documentOverride fallback has a precedence defect. A narrow version/count-guarded bundling correction, documented in `web/scripts/README.md`, preserves the per-instance Document adapter so style nodes receive the current nonce before insertion. No installed package/global DOM factory/CSP relaxation or upstream webpack build is used. Real Go HTTPS/Chromium tests cover split UTF-8/stderr, input/resize/signals, post-EOF output, validated status 7, actor-changing reauthentication without replacing the old execution, explicit disconnect, abrupt loss, exec/no-PTY and logout with retained sessions. They use a test backend through the real driver, not actual container/ConPTY processes.

## Browser resources and customization

Resources are served under `/_bifroest/files/<relative-resource>`; canonical HTML navigation renders `index.html`. A configured overlay wins per exact file before embed, including hashed names. Missing resources return 404, unsafe existing resources fail without embedded fallback, and directories are never listed. Requests share bounded worker/peer/rate budgets and write deadlines; all responses remain no-store, even when a hash filename is overridden. Index input is limited to 512 KiB, ordinary files to 8 MiB, with at most 64 local custom CSS and 64 custom JS inputs. Hidden/dot/encoded/device-name aliases, symlinks, multiply linked/nonregular or unstable files are rejected.

Ordered local CSS is appended after built-in styles; deferred local JS follows built-ins. Trusted head/body HTML is appended at the corresponding end; missing elements in an overlaid index are synthesized by the HTML parser. Fresh document nonces authorize inline script/style elements, not inline event handlers, eval or arbitrary remote script tags. Custom JS is trusted same-origin code and can use non-exportable keys. Register a `bifroest:configure` listener at script load to change its version-1 plain-text `detail.title`; initialization waits for DOMContentLoaded and emits this event before mount. `bifroest:ready` fires after React commit; neither event exposes access tokens.

The app exposes production/WASM notices and conservative component inventories. The normal build also creates `browser-build.json`, binding exact asset/input hashes, toolchains, revision/dirty state and local bundling patches as unsigned metadata, not source attestation. Release binary builds reject missing/stale/unlisted data; split packaging restores the binary host's digest-bound inventory. Archives/images include `BROWSER_BUILD.json`; combined notices and SPDX/CycloneDX include separate browser components and actual asset hashes. Builds reject absent license texts except explicitly version/hash-bound supplements. `web/licenses/README.md` distinguishes pinned publisher license text from still-unverified npm source-code correspondence. Generated files are not committed; source-only builds contain a marker, and `frontendAvailable` reflects actual index availability. Hosted release execution and signed provenance are separate evidence, not implied by the manifest.

## Schema examples

These are complete, parser-checked configuration examples for HTTPS. Apart from the explicit dummy test case, startup requires the indicated certificate/key files or successful ACME issuance for every domain. The built UI covers password/interactive/OIDC-device/local-key/RememberMe, shell tabs, structured Management metadata/confirmed session actions, paged artifact catalogs and client-only artifact verification/decryption/export/playback. The terminal API separately supports shell/exec. Forced-command equivalence and release integration remain incomplete.

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
