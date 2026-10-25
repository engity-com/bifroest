# Browser application and client core

The first React 19/Mantine 9 application supports password login, explicit
RememberMe opt-in, saved-access resumption, confirmed logout/revocation,
explicit local-only recovery and an owned xterm terminal. It uses en-US message
keys and memory-only auto/light/dark appearance. Local SSH-key import/signing now
uses an owned Go/WASM worker; Management has structured metadata and confirmed
session disconnect/dispose actions. Keyboard-Interactive
and OIDC device dialogs use the bounded existing server API. Vite 8/Oxc/Rolldown
builds the application and the independently tested, dependency-free HTTP/crypto
core; there is no Webpack/Babel chain or production Node runtime.

Use the repository-selected toolchains through MISE (Node 24.14 or newer), not
globally selected Node/npm versions. From the repository root (also native
Windows/Nushell compatible):

```text
mise run install:web
mise run lint:web
mise run install:web:browser
mise run test:web
mise run build:web
```

`build:core` writes `var/webui-client-build/`; `build:app` writes generated files
to `pkg/webui/assets/` before Go embeds them. Generated bundles are ignored;
only the source marker is tracked. Run the frontend build **before** building
the Go binary. A source-only Go checkout still compiles for SSH/API development,
but has no embedded UI until these resources are built. An `assetsDirectory`
containing a complete app can also supply the UI. Full release-job preparation,
aggregate SBOM/provenance integration and the remaining feature work are not done.

The app build also compiles `cmd/browser-key` with the pinned Go 1.27.3 toolchain
and copies that toolchain's `lib/wasm/wasm_exec.js`. The runtime must match the
reviewed SHA-256 in `scripts/browser-key.mjs`; no download or compatibility fallback
is performed. In restricted environments set `BIFROEST_GO_WASM_EXEC` to an explicit
operator-provided copy outside the output directory (the initial development
copy lives under ignored `var/webui-toolchain/`). No global Go/Node files are
changed. Source-only Go/SSH/API builds remain independent of this preparation.
Go/WASM notices are appended to the public notices; a separate conservative
component manifest records runtime/artifact hashes, Go version and actual external
module dependencies. This is not complete release-wide source provenance/SBOM.
Run `mise run lint:reuse` only after the app build has finished: Vite replaces
the generated output directory and restores its source marker during that build.

The optional real HTTPS/client/WebSocket test additionally uses the Go service
fixtures. After building, run the following from the repository root with
`BIFROEST_TEST_BROWSER_CLIENT=1` and, if necessary, `BIFROEST_TEST_NODE` pointing at
the selected Node executable (set these through your native shell's environment):

```text
mise x -- go test -race ./pkg/service -run '^TestBrowserRememberMeClientAgainstRealHttpsAndWebSocket$' -count=1 -timeout=90s
```

Set `BIFROEST_TEST_BROWSER_UI=1` for real UI/CSP/recovery tests and run
`mise x -- go test -race ./pkg/service -run '^TestBrowserLoginUi' -count=1 -timeout=90s`.
These tests exercise the actual embedded app, not a Vite proxy, under real Go
HTTPS with nonce-aware CSP, no unsafe-inline/eval and no framing. They cover
unchecked opt-in, real profile restart, discarded claim responses, explicit
local-only removal, disabled requesting-name collection, customization hooks,
theme changes and rejection of non-nonced inline scripts.

A requested browser run fails rather than skipping missing dependencies/assets.
Without the explicit opt-in, ordinary Go tests remain independent of npm/browser
installation. The owned self-signed HTTPS fixture is accepted only by that test
browser context, without changing any OS trust store.

Tests run in actual headless Chromium, including real IndexedDB structured cloning
of non-exportable CryptoKeys and an actual browser-process restart using an owned
temporary profile. The test fixture uses a secure-context loopback HTTP origin;
the real Go proof core supplies and verifies a challenge signed by the restarted
browser client's persisted key. Its native helper is test-only, never a web-action
or production CLI subprocess. This is not production HTTPS/login/UI coverage.
Browser installation is an explicit development/test
step and does not change the OS/browser trust store. Dependencies and compiler
versions are locked. Go asset serving now supports per-file FS-before-embed
overlays and ordered local customization. Structured Management, further runtime
coverage and complete release/SBOM integration remain subsequent steps.

The dependency-free `web/go.mod` is a tooling boundary, not a second Go runtime
or implementation: root `go test ./...` must not compile Go sources shipped in
`node_modules`. The interoperability helper explicitly runs in the root module.

`BrowserBinding.prepare` requires explicit opt-in and persists independent,
non-exportable P-256 signing and AES-GCM encryption keys before enrollment can
contact the server. `complete` stores only an encrypted flow/session/binding
selector. The only unencrypted record selectors are a hash of public origin/slug
and a random generation ID used for compare-and-swap. No primary private key,
password, access/attempt token, cookie or LocalStorage authentication is used.
Pending records cannot sign resume/revoke; ready records cannot enroll another
binding. Signing checks the server challenge's exact domain/purpose/scope/key and
stored binding, then signs the original bytes rather than reconstructed JSON.

Missing keys/state require regular login, never a selector-only fallback.
Corrupt/unsupported state fails closed without silent repair or key export.
`forgetLocal` deletes only this generation's local record; it is not a server
logout/revoke and must not be presented as one. A same-origin script can use the
keys, and non-exportability does not guarantee hardware/device binding or prevent
complete browser-profile copies. Other browser engines and browser/OS profile
protection still need runtime verification.

## HTTP orchestration

`BrowserClient.password` performs regular primary authentication and returns an
opaque `WebAccess` kept only in tab memory. Its JSON snapshot excludes its token.
RememberMe is a separate explicit `access.remember({ explicitOptIn: true })`
operation, so an enrollment failure does not implicitly discard a successful
regular login. `resume` requires the saved key and selector plus a new possession
proof, returning a new opaque permission rather than reattaching an execution.
`terminalToken` is intended solely for the first WebSocket open message. Existing
executions are never automatically closed merely because this token/binding expires.

All requests use native same-origin fetch, omit credentials/cookies, reject
redirects, bypass HTTP caching, carry proofs only in Authorization headers, and
bound each request to 20 seconds and each JSON response to 64 KiB. No auth token
goes into URLs, browser storage or JSON serialization. Internal diagnostics are
redacted and POSTs are never retried automatically.

A failure before enrollment proof can remove only this operation's new pending
state. Once a proof request may have committed, a lost/malformed response or
failed local completion is `outcome-unknown`: keep the pending key, do not replay
the claim, automatically revoke siblings, or pretend that no binding exists.
The original access's explicit `logout` can reconcile it through the server's
parent-permission binding link. Logout also stops new local access immediately,
cancels an active enrollment and waits for its local completion before CAS cleanup.
A pruned access token may fall back to fresh proof of only its own known binding.
An unrelated regular login never infers ownership from another actor's saved
record. Failed durable logout/revoke keeps the key/selector for an explicit retry;
a changed local generation is preserved rather than overwritten/deleted.

`forgetRemembered` performs fresh proof-based server revocation before local CAS
deletion. An existing registration is not silently replaced/revoked by a new
regular login; `already-remembered` requires an explicit user decision. Pending
ambiguous state requires regular login/recovery, never selector-only access.
Logout/revoke returns a separate local cleanup result after remote confirmation:
a changed/newer record or local-storage failure is not misreported as a failed
server revocation. A confirmation dialog calls `revokeSelection` with the handle
it actually showed, never silently adopting another tab's replacement.

The UI leaves existing registrations unchanged on ordinary login. Remote revoke
and local-only removal have separate confirmation dialogs; local removal never
claims server logout. Interrupted setup stays visibly uncertain until explicitly
reconciled. Artifact transfer/client-side decryption, exact forced-command
equivalence and portable Go-client transport integration remain subsequent work.

## Interactive and OIDC device login

Choose `Interactive / device login` to use the same Keyboard-Interactive/OIDC
authorizer path as SSH. Info/error steps require explicit acknowledgement;
prompts honor `echo` with plain or password input. Provider text is React text,
never HTML or terminal commands. HTTPS verification links are provider-supplied,
opened only by an explicit click with noopener/noreferrer; no iframe, automatic
redirect or OAuth token transfer is used. Disabled user collection still sends
the original empty requesting name; verified principal comes only from Go.

The client holds its `bwl1.` proof privately in the tab and handles one step and
one reply at a time. It enforces canonical increasing sequence 1–32, 8-KiB messages,
32-KiB cumulative text and 4096-byte well-formed answers. Ordinary pending polls
are spaced at least 1250 ms; while a dialog waits, 15-second keepalives refresh
only the existing attempt's idle budget, never its pinned hard expiry. There is
one logical interactive operation per client with a ten-minute cap and no
automatic retry of a failed reply or claim. Poll can consume the completed
authorization exactly once, so a lost reply/claim reports `login-unknown`, does
not adopt late access and requires fresh login. Abort and failure use an independent
bounded best-effort `login/cancel`, not logout/session disposal. Replies/attempt
tokens are never serialized, stored, reused for another step or fed to xterm.

Native Go HTTPS/Chromium tests cover info/error/plaintext injection resistance,
echo/secret transitions, one-time claim loss/recovery, actual signed local IdP
device login with no requesting name, RememberMe grant reuse, and cancellation
of a real in-flight IdP token request. The IdP is an owned test fixture; this does
not claim external-provider, native Local account-policy or public-key UI coverage.

## Public-key login and owned Go/WASM worker

`BrowserClient.publicKey(user, key, signal)` accepts a trusted tab-local `LoginKey`
adapter exposing only its canonical Base64 SSH public wire key and a scoped
`sign(challenge, expiresAt, signal)` operation. It shares the bounded one-time
attempt driver with interactive login, but accepts exactly one `public-key` proof
step, has a two-minute hard cap and never falls back to a password/interactive
prompt. It checks the original challenge domain, HTTPS origin/port, exact slug,
original requesting name (including empty), exact key/certificate fingerprint,
nonce, connection ID and pinned expiry before calling the signer. The reply must
be a strong canonical SSH wire signature, not WebCrypto P1363/ASN.1 or RSA/SHA-1.
No private key/passphrase property is serialized or sent to Go. Failed/ambiguous
replies and final claims are not replayed; cancellation affects only the attempt.

`pkg/browserkey` is the portable Go implementation used by the dedicated WASM
worker, not an HTTP private-key import endpoint. It reuses `x/crypto/ssh` parsers,
decryption and original SSH signatures; public parsing/challenge encoding/proof
verification are shared with the server. Imports are limited to one 64-KiB PEM
key, 4096-byte passphrase and optional single 12-KiB OpenSSH user certificate
matching the private key. Supported keys are Ed25519, RSA 2048–8192 and NIST
P-256/P-384/P-521. OpenSSH bcrypt is capped at 64 rounds before decryption.
Unencrypted PKCS#1/SEC1/PKCS#8 and supported legacy PEM/OpenSSH encryption use the
existing Go parser; encrypted PKCS#8, PPK, security keys and multi-key files are
not supported. Certificate import is not trust/authorization: current server
principal/CA/options/expiry rules remain authoritative. Every imported handle
can attempt one context-checked signature, including on failure. Close drops
references; Go/browser GC is not a physical-erasure guarantee.

The `SSH key login` form selects a local private-key file, optional passphrase
and optional matching user certificate. The app does not retain files/passphrases
in application state, storage records or HTTP fields; submitted inputs and the
component-local uncontrolled value are reset immediately. Private
inputs have no form names and the key form uses native `method=dialog`, preventing
a fallback native form upload. An explicitly selected empty certificate fails
locally, never silently falling back to a raw key. All bytes go only through
transferable buffers to an owned module worker after its runtime is ready.
The worker uses the portable Go parser/signature implementation, clears temporary
buffers, and is terminated after success, error, cancellation or deadline. RPCs
are capped at 20 seconds and an imported worker has a two-minute hard lifetime;
no detached/background import or reusable signing service is exposed. Close/GC
is not a claim of physical secure erasure or hardware-backed key storage.

Only the exact worker asset response enables `wasm-unsafe-eval`; the document
still forbids both JavaScript eval and WASM compilation. The worker permits only
same-origin modules/fetch and no child workers. WASM is downloaded lazily for
key login (currently about 7.7 MB uncompressed, below the existing 8-MiB asset
bound); it is neither a server subprocess nor a Node runtime. Speculative module
preloading is disabled so shared chunks cannot crowd out ordered customizing
scripts under unchanged shared per-peer admission limits. No automatic API retry
or admission-limit increase is used.

Native tests exercise all algorithms, encrypted imports, certificate matching,
canonical/duplicate/foreign/expired challenges, one-shot concurrency and unchanged
server policy. Actual TLS/HTTP2 tests import/decrypt a fixture locally, submit
only public key/signature, and join the same session as SSH. The package compiles
for JS/WASM. Actual Go HTTPS/Chromium tests run the Go/WASM worker with encrypted
Ed25519/RSA/NIST P-256/P-384/P-521 and plain Ed25519 files, wrong-passphrase local
failure without an auth request, worker-boot cancellation, valid and expired
certificates, independent RememberMe/reload/resume/logout, empty inputs after
submit, bounded private IndexedDB schema and no private HTTP fields/CSP violations.
RPC-fixture unit tests separately check bounds, explicit empty-cert rejection,
one-shot use, cancellation and deadlines; they are not cryptographic runtime tests.

## Structured Management

A Management environment uses the same login/RememberMe/access grant as terminal
flows, not a second admin login. The authenticated UI loads the management panel
only for that environment. `Load flows`, paged sessions/filters and session details
call fixed typed HTTP endpoints, never a terminal/SSH tunnel, CLI argument array
or command interpreter. Results reset on fresh authentication; late/cancelled
responses cannot appear under another actor. Data is live keyset paging rather
than an immutable complete snapshot, with at most 20 rows and 64 KiB per result.
Pagination cursors bind their operation/filters, but are selectors, not credentials.

The three POST endpoints are `management/flows/list`, `management/sessions/list`
and `management/sessions/show`, under the existing API prefix. Same-origin TLS,
tab-only Authorization proof, no-cookie/no-redirect fetch, shared API/admission
budgets and a 20-second request deadline remain unchanged. Each actual operation
acquires a fresh shared session connection lease, is registered for logout/global
revocation/disconnect, activates/touches only its own management session, and uses
the common task audit/recording/seal/final-audit driver. The small internal byte
capture is not a shell or a fabricated SSH session. Results stay buffered until
the complete configured audit/recording policy has succeeded.

Flow summaries and session view construction are shared Go operations with the
existing CLI. `pkg/management/protocol` holds portable typed data and cursor rules;
the existing SSH/CBOR formats and CLI behavior are retained. Session `user` and
`remote` are explicitly original requesting metadata. Verified issuer/subject
come only from an immutable stored association; legacy/anonymous sessions show
no invented owner/principal. Damaged entries produce a partial-data warning, not
private filesystem diagnostics or automatic cleanup.

The metadata adapter has no credential-detail or artifact route:
`includingCredentials`/`allowArtifactTransfer` cannot be asserted by a client.
Recognized forced read commands constrain the typed operation, data filters and
returned fields as described below. Unsupported forms and all forced mutations
stay fail-closed; continue using SSH with those restrictions rather than removing
them. Original artifact streaming uses separate typed endpoints below. Browser
artifact UI/Go-WASM fetch integration and client-only full artifact verification/
decryption remain open; the UI/JSON adapter is not a completed Go management client.

Tests include shared quota, own logout vs sibling grants, global revocation,
request cancellation, strict final-audit refusal before output, preserved damaged
state, paging and forced-command denial. Actual Go HTTPS/Chromium exercises flow
pagination, session tables/details, cookies/CSP boundaries and actor-changing
reauth with cleared data while the CLI application is deliberately unavailable.

### Forced read ceilings (conservative subset)

The server interprets only the **operator-configured** forced command, never a
browser command. Recognized forms are `flow ls`, `session ls` and `session show`
with one exact canonical session UUID. Supported output flags are `--format`
`table`/`json`/`yaml`/`cbor`; session lists also support `--flow`, `--user` and
`--state` with the same defaults as SSH (`active`). Unique `--name=value` and
`--name value` forms use the same POSIX token splitting as the SSH adapter.
Unknown options, duplicate flags, aliases/help/config-file expansion, shell
operators, malformed inputs, dispatcher/wire names and mutations are not inferred
as safe. Unsupported syntax remains denied even if another spelling might be
valid over SSH. No general CLI parser or command execution handles HTTP data.

Only the same operation is allowed; a session list cannot fetch details or prepare
disconnect/disposal. A fixed session show must keep its exact UUID and cannot use
an explicit HTTP flow to bypass the SSH global-ID ambiguity check. List results
apply the intersection of requested and forced flow/requesting-user/state filters;
requesting `all` or another user cannot broaden the ceiling, including subsequent
pages. Caller-provided flags cannot replace configured restrictions.
An additional `active` filter is accepted only if the forced list already uses
`active`: unlike an ordinary state filter it also tests the exact validity
deadline, so applying it to another forced state could disclose withheld or finer
time information through row presence. For other forced states, explicitly select
`all` or an ordinary exposed state rather than the UI's initial `active` filter.

Forced session reads do not expose the additional stored association owner. A
table list returns only its CLI data columns: ID, flow, state, requesting user and
created time; remote/last-access/valid-until are withheld. Other recognized list
formats and shows retain their normal base session metadata, never the extra
owner. Table/CBOR time values are reduced to whole seconds, matching the SSH
format rather than exposing finer precision. `policyLimited: true` explicitly
distinguishes withheld data from absent evidence or an unlimited lifetime; the UI
warns and disables mutation controls. Unrestricted permissions/data are unchanged.
Audit tasks mark such reads as forced. This is not complete ForcedCommand parity:
all mutation and dispatcher mappings, other CLI operations and unsupported forms
remain closed. Native SSH/HTTP reference tests compare actual formats/columns,
filter intersections and operation ceilings; a real Go/WASM key-login browser
test checks the limited view and denied detail/mutation access.

### Portable Go framing and artifact sinks

`pkg/management/wire` now owns the existing management request/result, recording
list/artifact and audit-snapshot framing. It imports only the portable protocol,
CBOR and standard library, not CLI/configuration/SSH/recording/audit server code.
The native Go management client uses it directly; `pkg/cli/transport` retains thin
compatibility adapters plus real native snapshot capture/FS sinks. The original
RecordingView tags/order and request wire bytes are pinned by compatibility tests.
Shared recording-page limits keep selector and decoder bounds in sync. This is
reuse of the existing implementation, not a second TypeScript artifact parser.

Readers retain bounded frames and exact explicit end/count/EOF checks. Audit
headers are completely validated before `AuditSnapshotSink.Begin`, including all
names, duplicate entries, positive/per-file/total lengths, canonical digests and
the required head. Duplicate CBOR header keys and nonportable/path/control names
are rejected before storage effects. `Begin` receives an independent file-list
copy; `Open` returns a provisional writer closed even on copy failure. Native
staging uses exclusive creation, never overwriting existing files. The caller
owns cleanup and publication: row callbacks or bytes received by a sink are not
complete/trusted results. Even successful digest/end/EOF decoding still requires
successful transport completion and independent full signature/producer/chain/
checkpoint/decryption verification. The native client's existing SSH-exit,
diagnostic-drain, cancellation and abort tests remain in force.

Unit tests run natively and as actual Go/WASM under the MISE-selected Node runtime
using matching workspace Go runtime copies; this is not browser worker/UI
integration. Typed original-artifact routes are described below. Artifact-key
import/decryption UI, browser fetch/WASM integration and immutable ReaderAt/full-
verification integration remain open. No CLI arguments become a browser protocol,
and no server decryption/key upload or new management permissions are introduced.

### Portable response completion

`pkg/management/client` now owns one already-open `Response` through typed
decoding, transport `Complete` and local `Close`. It never opens a connection,
interprets a command or retries/undoes an operation. Native metadata/public-key,
recording-list/artifact, audit-snapshot and fixed version readers use this same
core. Legacy wire encodings and native formatting remain outside its lifetime
contract; a typed HTTP adapter can supply its own bounded structured decoder.

`Complete` must report final operation success after joining the producer and
diagnostics, not merely a valid payload/end frame/EOF. Decoder or sink failure
calls `Abort` **before** waiting; cancellation can interrupt Read or Complete.
Abort runs at most once and must unblock both without waiting for the receiver.
The cancellation callback is joined before local release; Close also runs once.
Any decoding/completion/abort/close error or cancellation observed through cleanup
returns the zero typed result. Streaming callbacks/bytes remain provisional and
caller-owned; they cannot be rolled back or published by this receiver. Local
sinks must cooperate with cancellation: arbitrary blocked user writers cannot be
forcibly interrupted by a Go library. Expected recording/audit selectors are
checked before successful headers return; transport assertions remain untrusted.

The native SSH adapter alone owns its single Wait/exit-status check, bounded
diagnostics/drain, producer interruption and idempotent connection release. Its
handshake/start cancellation watcher is joined too. Real SSH tests cover malformed
data with EOF but a deliberately missing remote exit, fully valid data without an
exit status, nonzero exit, cancellation, bounds and diagnostic-output failure.
Portable lifecycle tests cover cancellation during reading/completion/cleanup,
joined callbacks, simultaneous causes, provisional rows/headers and panic cleanup;
they also execute as actual Go/WASM under Node. This is not browser integration.

The typed HTTP artifact response below supplies an explicit **post-driver final-
success** signal after recording seal/final audit; body EOF alone never counts.
This is still not a complete Go/WASM browser client. Browser CLI arguments,
private-key uploads and server-side decryption remain absent.

### Typed original-artifact HTTPS streaming

`management/artifacts/recording` accepts only `slug`, `auditlog`, canonical `id`;
`management/artifacts/audit` accepts only `slug`, `auditlog`. These are fixed POSTs
under the existing API prefix, with the same exact-scope tab bearer, direct TLS/
Host/SNI/Origin/peer checks, shared admission/start budgets and 20-second deadline.
The Management environment must enable its existing `allowArtifactTransfer` flag;
`includingCredentials` does not grant transfers and neither flag can come from a
request. All forced-command credentials remain denied for these operations.

Each transfer acquires a fresh common lease and uses the same typed environment,
activity/quota/revocation/task-audit/recording/seal/final-audit driver as SSH. The
same original sealed-recording/signed-audit-snapshot writers serve both adapters,
without CLI parsing or an SSH-shaped task. No server decryption identity is used.
Transfers remain live children until response delivery/cleanup; own logout closes
only the owning grant's children, not another grant or the session/workload.

The response media type is `application/vnd.bifroest.management-transfer.v1`.
A fixed magic precedes 32-KiB-bounded data frames containing the unchanged legacy
artifact envelope. An empty data-end frame ends only data. After successful common
driver completion and access checks, a separate bounded canonical CBOR completion
binds the exact operation/auditlog/ID to data count and SHA-256, followed by HTTP
body EOF. Absent/duplicate/mismatched/trailing/malformed completion fails closed.
Data totals retain the native 32-GiB recording or 1-GiB audit plus bounded header
limits; there is no whole-artifact server buffer or timeout/limit increase.

The portable Go `NewHTTPTransferResponse` checks status/media/encoding, owns the
body and implements the shared receiver's Read/Complete/Abort/Close contract. It
does not open requests: the opening adapter must separately guarantee TLS/origin,
scope/bearer, omitted cookies and redirect refusal. Staging bytes remain
provisional until completion; its transport hash never replaces independent
signature/producer/checkpoint/full-decryption verification on immutable inputs.

Real TLS/HTTP2 tests transfer clear/encrypted signed artifacts with the CLI app
unavailable, independently verify evidence, and prove data-end cannot bypass
blocked/failed final audit, failed recording seal, logout/revocation/cancellation.
Protocol/Go-WASM tests cover frame bounds, selectors, canonical completion, physical
EOF and body ownership. This adds no artifact download button, browser fetch bridge
or decryption/key-import UI; those remain subsequent work.

### Portable recording evidence verification (not yet browser UI)

`pkg/recording/cast` now contains the existing complete Cast/v3 and native
`.bcast`/`.becast` verification/decryption/export implementation, not a replacement
parser. Native `pkg/recording` entry points delegate to the same code. Key values
and age SSH payload cryptography live in `crypto/keydata`; `nativeformat` no
longer imports native key files/bootstrap/OS code. Public producer/task data and
Cast-signature consistency checks live in `audit/evidence`. Session, connection
and recording IDs remain **distinct types** with their existing JSON/binary/
MsgPack codecs; native names/APIs are aliases, not new wire schemas or a migration.

Outer verification authenticates the signed committed envelope only. Complete
native verification additionally decrypts/authenticates age through EOF, checks
bounded single-frame Zstd/CBOR events, reconstructs Cast, verifies semantics/
signature/digest/counts and checks the same physical input across passes. Export
starts only after full verification and rereads the **same immutable ReaderAt**;
an output failure can still leave a partial already-verified export, so callers
own atomic staging/publication. Incremental renderer/decoder APIs are explicitly
provisional and must never be presented as a full/trusted verification result.
`Trusted` requires a separately expected producer; internal signature consistency
or an artifact/transfer header never supplies that trust. Untrusted verification
is still an explicit, separately labeled opt-in, not a fallback.

Native identities/private-file ownership/mode/ACL/bootstrap policy, repositories,
durable recording commit/recovery and restricted audit signers remain native.
The shared signer interface grants no new server RPC/signing operation and the
client verifier loads no key files. Frozen existing clear/encrypted vectors run
as actual Go/WASM under MISE/Node, including full decryption and byte-identical
Cast export, wrong/missing key/producer, tamper/truncation/trailing input, canceled
verification, changed ReaderAt between passes and no plaintext before verification.

This does not add the browser fetch/WASM bridge, key-input/decryption controls or
verified artifact UI. Audit journal verification still uses its native immutable
filesystem snapshot/tree checks; extracting a real portable journal-reader
capability remains open. It must not be replaced with fake OS/process/filesystem
stubs, transport hashes or a second implementation of journal verification.

### Confirmed session actions

`Disconnect session connections` and `Dispose session` are available from the
selected session detail. Opening the dialog makes an audited/recorded preparation
read, not a target mutation. The server returns a one-minute one-use `bmc1.`
permission, hash-indexed only in memory and bound to the exact original access,
origin/slug, direct peer, action and immutable creation/association evidence for
the target. It is not standalone authentication. At most 64 preparations/four per
peer are retained; preparation also shares existing start/request budgets. Read
activity never extends the pinned expiry. The dialog shows the fresh target,
verified owner evidence and creation time, and requires typing the exact
`flow/session ID`. Closing an unused dialog only cancels that preparation.

`management/sessions/prepare`, `confirm` and `cancel` are fixed POST endpoints.
Confirm/cancel use the original access bearer plus a body-only confirmation token;
they accept no replacement action/target. A confirm consumes its one-use permission
before any possible effect, including on failure, and retains its slot while the
operation actually runs. Target generation is rechecked immediately before use
and after the started-action audit; this is not a filesystem transaction against
a privileged operator concurrently rewriting protected storage. A replaced target
or the caller's own management session cannot be operated on. The shared SSH
session-control implementation owns disconnect/revocation/disposal, cross-flow
audit and durable-disposal-before-cleanup; the common task/recording/final-audit
lifecycle remains mandatory. No CLI parser or new administrator role is used.

Disconnect closes the current connection snapshot, but permits a deliberate new
connection in the same session/workload. Dispose revokes access, stops refresh,
persists disposal and performs normal environment/authorization cleanup; partial
failure may already have revoked access or removed resources. Own browser logout
is still not disposal. Any lost/malformed/cancelled commit response is
`management-unknown`, never a replay, success or rollback. The local handle can
confirm once and cannot turn later cancellation into undo. The UI retires stale
results, clears old target data and allows explicit metadata reads. Authentication
changes stay locked during commit/unknown outcome until the result is confirmed
or the user explicitly dismisses the local warning (which confirms nothing).

Actual HTTPS/Chromium drives two live WebSocket executions, unused-dialog cancel,
typed-target confirmation, disconnect plus a new execution in the same session,
and dispose with a deliberately lost successful response. It verifies revoked
state through an explicit read and no automatic confirmation replay. Native/race
tests cover concurrent one-shot claims, peer/scope/original-grant binding,
self-protection, expiry/cancellation, bounded retention, changed generations and
final-audit failure after a possible effect. Existing SSH controls remain covered.

## Terminal ownership and limits

The xterm/fit modules load after terminal-flow authentication. `Start new
execution` owns exactly one new WebSocket shell/exec, optionally with PTY; no
automatic reconnect/reattach or management CLI fallback exists. The proof is
resolved fresh only for the first open message, not stored in the URL,
subprotocol, terminal output or serialized state. Resize, binary/text input,
EOF half-close and INT/TERM requests use the existing strict Go wire contract.
Input is copied/bounded to 64 KiB and paced (4-KiB chunks, conservative 40-KiB/s
budget, small interactive frames no faster than 22 ms, controls at least 100 ms
apart, 16 queued controls). Overflow closes with an explicit error instead of
silently truncating/replaying a paste. Native socket buffering is capped before
more sends, with a five-second blocked-write budget.

Decoded output frames are at most 16 KiB, at most 64 jobs/256 KiB may queue behind
one xterm writer, and each renderer job has a five-second budget. The original
UTF-8 byte stream is passed to xterm without per-frame decoding. Final output is
drained before a validated uint32 exit is published. Clean/abnormal close without
an exit is unknown, not status zero. Timers, observers, socket callbacks and
renderer generations are owned/disposed; old renderer jobs drain before reset so
they cannot bleed into a new execution/actor. Scrollback is 1000 lines. Remote
OSC clipboard requests, application-title mutation, window operations and link
activation are not enabled. Theme follows the same computed UI color scheme.

New-access expiry/reauthentication does not replace a running execution. The
terminal keeps its immutable actor-at-start label while a fresh login is used
only for a subsequent start. Explicit tab logout disconnects owned UI transports
without session disposal or adopting another actor's stored binding. An
uncertain enrollment's original parent is kept for logout/reconciliation instead
of being lost through a new login.

xterm 6.0.0's documentOverride precedence error requires a version/count-guarded
local bundling correction; see `scripts/README.md`. The supported per-instance
Document adapter nonces style nodes before insertion. No global DOM patch,
unsafe-inline/eval, iframe or upstream build/webpack command is used. The app
component inventory records the modification. Native Go HTTPS/Chromium tests
verify actual xterm I/O, split UTF-8, stderr, resize/signal, post-EOF output,
explicit exit, actor-changing reauth, new runs, abrupt loss, exec without PTY,
logout, retained sessions and strict CSP. The backend is a test hook through the
real service/recording/lease driver, not real Docker/Kubernetes/ConPTY coverage.

## Public resources and customization

Built bundles/images/fonts are served at `/_bifroest/files/<relative-resource>`;
`index.html` is rendered only for canonical navigation paths with HTML Accept.
JSON Accept keeps discovery metadata. Overlay files win per exact resource name,
including hashed bundles; only absence permits embedded fallback. Unsafe existing
files fail closed. Static responses are no-store even for hashed names, so an
operator override is not hidden behind stale immutable caching. Root descriptors
stay anchored until restart; updating individual files is visible, replacing the
root directory requires restarting. Symlink and hard-link aliases, hidden/dot/
device-name/encoded paths, directories and oversized files are rejected. Index
input is limited to 512 KiB, ordinary resources to 8 MiB; there are at most 64
custom CSS and 64 custom JS files.

Go adds fresh per-document script/style nonces, including to trusted inline
operator HTML and Mantine styles. Remote script tags are not granted a nonce;
inline event handlers/eval/framing remain blocked. Missing head/body elements in
an overlay are synthesized by the HTML parser. Ordered `customCss` is appended
after built-in styles; deferred local `customJs` follows built-ins. Register
`window.addEventListener('bifroest:configure', e => { e.detail.title = 'Brand'; })`
at script load to customize the initial plain-text title. Initialization waits
for DOMContentLoaded and dispatches this version-1 event before mount;
`bifroest:ready` is emitted after React commit. Neither event exposes access tokens.
Custom JS is trusted same-origin code and can use browser keys; non-exportability
does not defend against malicious same-origin code.

The app includes `third-party-licenses.txt` and a conservative production npm
dependency inventory `frontend-components.json`. Builds fail on missing license
texts except explicitly version/hash-bound supplements. See `licenses/README.md`
for the documented license-text/source-code provenance distinction; this is not
a claim of complete release SBOM or tarball/source verification.
