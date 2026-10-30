# Browser application and client core

The React 19/Material UI 9 application supports password login, explicit
RememberMe opt-in, saved-access resumption, confirmed logout/revocation,
explicit local-only recovery and an owned xterm terminal. It uses en-US message
keys and memory-only auto/light/dark appearance. Local SSH-key import/signing now
uses an owned Go/WASM worker; Management has structured metadata and confirmed
session disconnect/dispose actions. Keyboard-Interactive
and OIDC device login use a local authentication-terminal tab and the bounded
existing server API. Material tabs and SVG icons share one UI theme. Default tab
labels show only the verified principal; flow/connection details stay in tooltips
and menus. The terminal view owns its padding and matching background. Vite 8/Oxc/Rolldown
builds the application and the independently tested, dependency-free HTTP/crypto
core; there is no Webpack/Babel chain or production Node runtime.

Use the repository-pinned Bun 1.4.4, Biome 2.6.3 and Node 26.9.0 through MISE.
The root and nested Web Node pins agree. Do not
rely on globally selected runtimes. From the repository root (also native
Windows/Nushell compatible):

```text
mise run install:web
mise run lint:web
mise run install:web:browser
mise run test:web
mise run build:web
```

The root `install`, `lint` and `test` tasks include their Web counterparts;
Chromium installation remains an explicit `install:web:browser` step. The
`build:go` task depends on `build:web`, so embedded resources precede the Go build.
The split CI binary tasks consume the separately built, validated browser bundle.

The repository-root `biome.json` formats and lints owned TS/JS, JSON/JSONC and
YAML files, including tests, declarations and build scripts. `mise run lint:biome`
checks the whole repository without installing frontend dependencies;
`mise run lint:web` checks
formatting, recommended lint/import rules (warnings fail) and TypeScript types.
The shared style uses two spaces, 100 columns, single JS quotes, semicolons,
block statements and separate variable declarations. To format deliberately:

```text
mise run format
mise run lint:biome
```

`biome.json` uses the repository ignore rules; generated bundles, Go's pinned
runtime, Bun's generated lockfile, byte-exact audit/recording vectors and
`node_modules` are not reformatted. The few local suppressions explain
intentional security behavior (actor-reset dependencies, void acknowledgements,
cookie-only authentication rejection tests), not a disabled lint category.

Bun is the package manager and script launcher: `install:web` uses the committed
`bun.lock` with `--frozen-lockfile --ignore-scripts`. `bunfig.toml` explicitly keeps
the hoisted dependency layout. Vite/Vitest and Go/WASM/interop helpers still run
under Node; this is not a Bun runtime migration. Use `bun run test`, **not**
`bun test`, to retain Vitest's real-browser tests and the restart helper.

The build's conservative production license/component inventory reads `bun.lock`
as checked JSONC, walks production dependencies and installed peers/optional
dependencies, checks installed names/versions against lock entries and records
the locked archive hashes.
Development-only tools are excluded. Unsupported lock schemas, non-flat layouts,
aliases/non-registry sources, missing packages or license texts fail the build
instead of producing an incomplete manifest. Archive integrity is lockfile
metadata, not an assertion that the installed tree or bundled output is byte-exact
upstream source. The existing license-text supplement is not source provenance.

`build:core` writes `var/webui-client-build/`; `build:app` writes generated files
to `pkg/webui/assets/` before Go embeds them. Generated bundles are ignored;
only the source marker is tracked. Run the frontend build **before** building
the Go binary. A source-only Go checkout still compiles for SSH/API development,
but has no embedded UI until these resources are built. An `assetsDirectory`
containing a complete app can also supply the UI. Release jobs include the browser
bundle, combined notices and SPDX/CycloneDX inventory as described below. These
unsigned inventories are not a signed source-provenance or reproducibility proof.

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
Without the explicit opt-in, ordinary Go tests remain independent of Bun/browser
installation. The owned self-signed HTTPS fixture is accepted only by that test
browser context, without changing any OS trust store.

The opt-in `TestOpenSSHKubernetesBrowserSharedWorkload` uses the existing E2E
harness to create and remove its own kind cluster, image and scoped kubeconfig,
not the user's current Kubernetes context. It drives real OpenSSH and the built
HTTPS/key-WASM/xterm UI against the same Kubernetes environment. It checks one
session/Pod UID/target account, distinct connections across reload, shared marker
state and preservation after browser logout, then verifies the signed recordings
and audit correlations after shutdown. It is distinct from Dummy-backend tests.

`TestOpenSSHDockerBrowserSharedWorkload` exercises the Docker environment through
the same HTTPS/key-WASM/xterm UI and OpenSSH. It independently inspects the full
container ID and marker before and after the browser runs. Its first browser run
is a PTY shell with real xterm input and exit code 7; after reload and explicit
login, a fresh non-PTY exec exits with 0. Four distinct execution connections must
share one session, effective UID and persistent container, with verified signed
recordings and matching audit operations. The Docker E2E matrix runs this test
with both Docker Engine and Podman's Docker-compatible API; a skipped browser
test fails the CI step.

After `mise run build:web` and browser installation, select the runtime explicitly
with `BIFROEST_E2E_RUNTIME=podman` (Docker is not required), set
`BIFROEST_TEST_BROWSER_UI=1` and `BIFROEST_TEST_NODE` to `mise which node`, then run:

```text
mise x -- go test -tags=e2e -run '^TestOpenSSHKubernetesBrowserSharedWorkload$' ./test/e2e -count=1 -timeout=30m
mise x -- go test -tags=e2e -run '^TestOpenSSHDockerBrowserSharedWorkload$' ./test/e2e -count=1 -timeout=15m
```

Set environment variables using your native shell syntax. On Linux, choose a
short private temporary parent such as `/tmp/opencode` for both `TMPDIR` and
`GOTMPDIR`: long workspace paths can exceed the Unix socket-path limit used by
the Podman API fixture. Existing `mise run test:e2e:kubernetes` and
`mise run test:e2e:docker` remain the native SSH/recording baselines; their current
selectors do not include the browser tests. CI selects the Docker browser test
separately after building the frontend and installing Chromium. Both existing
kind jobs now likewise require the Kubernetes browser test after their native
SSH/recording baseline. The Docker-backed kind job runs on matching pull requests;
the Podman-backed job retains its schedule/manual-only trigger. Missing test
execution, a skip or a failure rejects the browser step; no user's kubeconfig
context is adopted.

Tests run in actual headless Chromium, including real IndexedDB structured cloning
of non-exportable CryptoKeys and an actual browser-process restart using an owned
temporary profile. The test fixture uses a secure-context loopback HTTP origin;
the real Go proof core supplies and verifies a challenge signed by the restarted
browser client's persisted key. Its native helper is test-only, never a web-action
or production CLI subprocess. This is not production HTTPS/login/UI coverage.
Browser installation is an explicit development/test
step and does not change the OS/browser trust store. Dependencies and compiler
versions are locked. Go asset serving now supports per-file FS-before-embed
overlays and ordered local customization. Structured Management, local artifact
verification/decryption/playback and release inventories are implemented below;
additional browser engines and OS-specific browser paths need separate runtime
acceptance rather than being inferred from these Chromium fixtures.

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

Local password/keyboard-interactive RememberMe now supports the non-PAM Linux
repository backend (`pamService: ""`). Enrollment/resumption use fresh readonly
passwd/group/shadow snapshots before and after current policy validation, with
the stored name/UID pinned and no primary-secret replay, cached-lookup fallback,
historical environment or saved rights. Locks, expiry/required password changes,
ambiguous or changed records, unavailable files and input limits fail closed;
files are limited to 16 MiB/100000 records and use nonblocking opens/file locks.
Rejected claims do not slide bindings or repair session/account state. Real owned
TLS/HTTP2/WebSocket and Chromium profile-restart tests cover both supported methods,
including logout without session/workload disposal; they create no host account.

PAM-enabled Linux also supports an explicit server-side `pamAccountResumeAllowed`
opt-in, default false. This combines the fresh local checker with a new
`pam_acct_mgmt` transaction before and after current request validation, retaining
the exact name/UID and new PAM environment. It never calls `pam_authenticate`,
answers a PAM prompt, reuses a historical environment, changes a password or opens
a PAM session. Operators must ensure that the PAM account stack enforces all
restrictions required during resumption; this is not general PAM-auth/MFA
equivalence. Current method/empty-password policies still apply. Darwin PAM and
Windows SAM password resumption remain unavailable. The isolated native
`mise run test:e2e:pam` harness additionally verifies real PAM policy, service
restart and browser profile recovery; see `test/pam/README.md` for its boundaries.

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
reconciled. Artifact transfer, client-side verification/decryption and the shared
portable Go transport receiver are implemented in the sections below. Exact
ForcedCommand equivalence beyond the documented read subset remains incomplete.

## Artifact transport core

`WebAccess.downloadArtifact({ kind: 'recording', auditlog, id }, signal)` and the
`{ kind: 'audit', auditlog }` form use the existing fixed artifact POSTs and
Management permission. No command, arbitrary path, decryption key or private
credential field is accepted. A tab owns one active transfer per access object;
logout aborts it and joins fetch cleanup without disposing the shared session.

The opening adapter enforces exact HTTPS origin/path, no redirects/query/cookies,
the transfer media type, no Content-Encoding and bounded actual EOF. Its body is
still provisional: a short-lived Go/WASM worker reuses `management/client.Receive`
and the native recording/audit wire decoders to check exact selectors, all data,
post-driver completion and genuine EOF. DataEnd alone cannot release a result.
The worker receives neither bearer nor private keys and is terminated before
success/failure returns. Errors do not expose parser or storage diagnostics.

The first adapter stages **tab memory only**, with 64 MiB of artifact payloads and
a 72-MiB bounded framed response image. There is no OPFS/IndexedDB staging or
persistent plaintext. Larger input returns `artifact-too-large`; the server's
32-GiB recording/1-GiB audit limits and authorization remain unchanged. Native
large-artifact support is not claimed as browser large-file support. The received
Blobs are immutable, but the HTTP response is currently buffered before Go
decoding; this is not a disk-backed or zero-copy streaming browser sink.

Successful results explicitly carry `transport: 'complete'` and
`evidence: 'unverified'`. Header Producer/Recipient/SHA256 values remain untrusted
transport assertions, never signature/trust/decryption proof. The separate
Recording/Audit evidence worker below must be invoked separately. The built
artifact view makes this an explicit action, never an implicit transport result.

The MISE app build adds `cmd/browser-transfer` and the one-shot
`browser-transfer-worker.js`; only the three exact key/transfer/evidence workers
receive the narrow WASM CSP. Parent documents and other scripts retain their
existing policy. The runtime comes from the same version/hash-checked selected
GOROOT as key login. The conservative transfer component manifest records its
actual dependency versions, reviewed/pinned MIT license texts and WASM/runtime
hashes; this is not complete release-wide source provenance/SBOM.

## Client-only evidence API

`verifyArtifact(received, options, localKey, signal)` owns a separate short-lived
worker. It accepts only completed immutable transport Blobs, explicit options and
an optional local File/passphrase. No bearer, URL, command, server action or key
filename enters the RPC. File inputs are read with abort support, transferred as
buffers and cleared where possible; worker termination retires the operation.
This is tab memory only, not persistence or a physical secure-erasure guarantee.

Options explicitly select an independent `producer` pin (or `allowUntrusted`),
expected `recipient`, `level: 'outer' | 'private'`, export intent and, for Audit,
`auditScope: 'complete' | 'captured-prefix'` plus private-field output opt-in.
Transport-header identity hints are never copied into these expectations.
Results keep signing trust, validation level, decryption and bytes-only source
provenance separate. An outer result emits no export. Only successful private
verification can return an output Blob; a failed key/producer/input/resource
check returns neither metadata success nor partial plaintext. A zero private
record count does not claim a matching key or any decrypted records.

The Go adapter reuses native Cast/Recording and Audit-producer verifiers and
exporters, not a second JS verifier. Recording passes share one owned immutable
ReaderAt image; Audit uses immutable images plus the shared canonical native
segment-name parser. Whole-file/chain/head checks and resource completion precede
JSONL/Cast publication. Audit default output remains redacted even when supplied
keys validate private semantics. Logical byte aliases make no filesystem claim;
native inode/link/tree guards remain native and stricter where applicable.

Local PEM/OpenSSH import shares the login parser's 64-KiB key / 4096-byte
passphrase / bounded bcrypt envelope policy. Evidence age decryption accepts the
existing Ed25519/RSA SSH identities only, matches their public fingerprint to the
independent recipient expectation, and never sends private values to the server.
Client raw input/output remain bounded at 64 MiB; writer failure discards the
staged export. The Worker has a hard two-minute lifetime, with bounded boot.

The larger evidence WASM is distributed as `browser-evidence.wasm.gz` (roughly
3 MiB); the general 8-MiB asset limit is unchanged. Its loader enforces compressed
EOF, gzip integrity and a separate 24-MiB decompressed limit before compilation.
Only the exact external evidence-worker response gets narrow WASM CSP, never
the parent document or ordinary scripts. Build manifests pin actual module
versions and reviewed license text hashes (including nested compression-library
notices), plus compressed/raw/runtime hashes. This is not full release SBOM or
cryptographic supply-chain provenance.

## Artifact verification/decryption view

The Management workspace lazily loads `ArtifactPanel`. Browse paged auditlog and
sealed-recording metadata or supply an exact auditlog/recording ID manually.
Local recording playback is described below. Download uses the existing `WebAccess`
API, transfer permission, quota and common server audit/recording lifecycle.
Forced-command credentials still cannot transfer artifacts; no new role or
client-selectable policy flags were introduced.

`WebAccess.managementAuditlogs(options, signal)` and
`managementRecordings(auditlog, options, signal)` use the fixed
`management/auditlogs/list` and `management/recordings/list` POSTs. They keep the
existing Management metadata rights: `allowArtifactTransfer` is still required
only for content transfer, while `includingCredentials` never expands the fixed
DTOs. A configured `audit ls` ceiling permits only the equivalent auditlog summary
list; other forced commands and all forced recording enumeration remain denied.
No private keys, credentials, paths or complete settings objects are returned.

Pages are at most 20 entries/64 KiB, with existing operation/filter-bound `bmp1.`
selectors; recording cursors additionally bind the selected auditlog and canonical
recording ID. Old flow/session cursor filters and native 1000-row recording bounds
are unchanged. Shared Go auditlog-view construction and native sealed inventory /
recording inspection/close paths are reused, never a CLI subprocess or terminal
table parser. Recording pages also use the existing heavy-operation start budget.
One native lookahead ID determines `next`, but only displayed
recordings are inspected. Corrupt selected evidence fails the whole buffered page;
unselected lookahead content is not verified or promoted into evidence.

Catalog rows are server metadata only, including `verificationScope`, producer ID
and recipient. The native encrypted format remains `becast-cbor/v1`. Choosing a
row sets only download selectors, clears old local evidence/expectations, and does
not fetch content or populate trust pins. Disabled auditlogs remain visible as
configuration metadata. Reads are explicit, never automatic on login/selection.
Completed same-actor pages can remain visible while other artifact work disables
selection; cancellation joins the owned request and rejects late/partial pages.
Authentication changes/logout clear actor-owned catalog state.

Unverified server hints/original files are labeled separately from independent
producer/recipient expectations. Expectations start empty and selecting another
artifact resets them, including untrusted/private/export/sensitive opt-ins. The
user explicitly selects expected encryption and outer or full private validation.
Only explicit untrusted mode permits a missing producer pin; results never call
that producer independently trusted. Audit scope, missing freshness and bytes-only
provenance are shown separately. Code served by the source server is not an
independent offline verification environment.

Full success can prepare a Cast/JSONL export without saving it automatically.
Audit output is redacted by default; private verification does not opt into private
output fields. Original bytes can also be saved deliberately, labeled unverified.
One owned Blob URL is retained at a time and revoked on replacement, result/options
change, discard, authentication/disabled transition or unmount. A browser save
click is not filesystem-write confirmation; discarding tab data cannot delete
previously saved files. Original inventories are displayed twenty files per page.

Local file/passphrase inputs have no upload names and use a prevented dialog form,
not a POST fallback. Native inputs and component-local uncontrolled state clear on submit,
expectation change or cancel; reselect the key for every attempt. Errors expose no
parser/private diagnostics or partial verified output. Generation/operation guards
refuse late results and retain the cancellation slot until joined cleanup finishes.
Logout, actor changes and disabled transitions retire workers, inputs, results and
owned URLs. No authentication/secret/plaintext is persisted by this view.

Actual HTTPS/Chromium/Go-WASM tests exercise clear/encrypted recording and audit,
independent and wrong pins, wrong passphrases, explicit untrusted state, full vs
outer, redacted/sensitive exports, captured scope, save/discard, cancellation,
actor-change cleanup and logout during incomplete transfer. Separate local-URL
tests cover ownership/failure/filename bounds, not a second cryptographic verifier.

## Release build and inventories

Use only the MISE-selected toolchains: `mise -C web install`, then
`mise -C web run install:web`, `mise -C web run build:web` and
`mise -C web exec -- bun run test:release`. Both root and nested
`web/.tool-versions` pin Node 26.9.0; the root Go pin remains 1.27.3. Bun is 1.4.4;
installation is frozen and lifecycle scripts are disabled.

The normal frontend build writes `browser-build.json`: exact asset lengths/
SHA-256s, conservative npm/Go-WASM/runtime components, pinned toolchains, the
checkout revision, explicit relevant-input dirty state, project Go/WASM inputs,
lockfiles/build scripts and the local xterm bundling patch. It is **unsigned build
metadata**, not a source-equivalence, tree-shaken-usage or reproducibility proof.
Npm integrity describes the locked source archive, never the shipped bundle hash.
License supplements remain text-only evidence with their original caveats.

`cmd/build` refuses release binaries without this complete inventory, the expected
revision, exact current inputs and the exact listed asset set; it checks again
after compilation. API-only source development with direct `go build` remains
available. An explicit `BIFROEST_GO_WASM_EXEC` development override intentionally
does not produce a release-eligible manifest. Local modified inputs are marked
dirty; GitHub Actions refuses dirty browser inputs.

Binary-build metadata v2 binds the platform/revision/build time, binary, combined
notices and a per-platform `.browser-build.json` sidecar by digest. A separate
packaging host restores and validates these files; it neither rebuilds the UI nor
substitutes its own frontend. Version-1 binary metadata cannot prove the browser
inventory and must be rebuilt, not silently upgraded. Archives contain
`BROWSER_BUILD.json`; images put it beside the existing release legal resources.
The release manifest records `browserBuildDigest` for each archive variant.
Third-party notices include all four frontend/WASM notice texts. SPDX 2.3 and
CycloneDX 1.6 describe the embedded assets with their actual hashes and add separate
browser dependency contexts, including modules absent from the native binary.
Source archive integrity and asset bytes remain explicitly different evidence.

The shared workflow builds/checks/tests one pinned browser bundle and downloads
that exact artifact before Go embedding on each binary host/container. All
checkouts prefer the resolved commit over a moving ref. Web-only changes trigger
the existing backend/release checks. Configuration/unit/local packaging checks are
not hosted Actions, Darwin-signing or Docker-engine execution evidence. No new
publish operation or cryptographic source attestation is introduced here.

## Local recording playback

After successful full private recording verification with export explicitly
requested, `RecordingPlayer` can prepare that immutable local Cast Blob. It does
not automatically prepare or play, and outer-only/Audit results expose no player.
`prepareRecordingPlayback(blob, { id, producer, allowUntrusted }, signal)` uses a
fresh one-shot instance of the existing evidence worker, with independent caller
expectations rather than server hints or a producer pin manufactured from metadata.
It receives no bearer, URL, decryption key or server operation. The Go core checks
the exact Cast/ID/producer/signature/real EOF again; no provisional frame escapes.
This additional Cast check does not invent original-source, native outer-container,
decryption or freshness evidence; those remain in the preceding evidence result.

`cast.InspectCastEvents` is the existing complete Go verifier with a provisional
event visitor, not a second Cast implementation. It preserves cumulative intervals,
stdout/stderr/terminal identity, validated resize events and exact raw output bytes
from signed Bifröst event metadata, including invalid UTF-8. Input events remain
forbidden; markers/exit/unknown events retain timing but are not executed. The
browser parses only a small fixed-header renderer transport, never Cast JSON or
recording cryptography. Only complete success publishes an exclusively owned image.

The adapter limits input/plan to 64 MiB, all visited events to 100,000, dimensions
to 512 columns/256 rows and 32,768 cells. Valid recordings beyond these rendering
bounds are rejected, not clamped/truncated; native limits stay unchanged. Worker
boot/operation, compressed/decompressed WASM and document CSP bounds are unchanged.
Output frames are copied before asynchronous rendering, never exposed as mutable
views of the owned image; discard retires buffers where possible, not a physical
memory-erasure guarantee.

Playback uses a separate read-only xterm with bounded scrollback and no input,
socket, EOF/signal, command or execution capability. Recorded links, titles, window
operations and OSC 52 clipboard requests cannot activate host actions. Play/pause,
0.25–8x local speed, reset and discard affect only this renderer. Timers use a
monotonic clock with approximate browser scheduling, at most one <=64-KiB write
and bounded work per turn. Reset joins outstanding output before clearing; failed
or timed-out output cannot become successful completion or an unsafe reset.
The recorded outcome/exit status remains distinct from local playback completion.
Option/source changes, cancel, logout, actor changes and unmount retire workers,
timers, images and the private viewport, without discarding the persistent workload
or starting any network API/terminal operation.

Native/actual WASM tests cover frozen byte-exact output/resize/timing, trust/ID/
EOF/cancellation, genuine signed oversized/event-flood inputs and no partial plans.
Browser lifecycle tests separately cover opaque wire ownership, timing/speed,
drain/reset/timeout/dispose and bearer-free RPC, not a fake Cast verifier. Actual
HTTPS/Chromium verifies/decrypts clear/encrypted originals and drives manual local
play/reset/replay/pause, no API/socket calls, ignored OSC host actions and cleanup.

## Interactive and OIDC device login

Choose `Interactive / device login` to use the same Keyboard-Interactive/OIDC
authorizer path as SSH. Info/error steps require explicit acknowledgement;
prompts honor `echo` in a local xterm authentication console, not a modal response
form. This console has no WebAccess, WebSocket, remote command or recording sink.
Provider text remains plain text: terminal controls are rendered visibly rather
than interpreted, and secret answers never enter rendered output. A multiline
paste cannot answer a later prompt. IME gestures retain their original prompt;
overlapping paste/submission or a changed owner cancels the ambiguous attempt,
including during xterm's delayed commit. Secret preedit never reaches xterm's
visible composition node, and its secret-key screen-reader mirror is disabled;
the prompt remains available in a separate safe live region. OS candidate popups
are outside this application's control. HTTPS verification links are provider-supplied,
opened only by an explicit click with noopener/noreferrer; no iframe, automatic
redirect or OAuth token transfer is used. Disabled user collection still sends
the original empty requesting name; verified principal comes only from Go.

The client holds its `bwl1.` proof privately in the tab and handles one step and
one reply at a time. It enforces canonical increasing sequence 1–32, 8-KiB messages,
32-KiB cumulative text and 4096-byte well-formed answers. Ordinary pending polls
are spaced at least 1250 ms; while a prompt waits, 15-second keepalives refresh
only the existing attempt's idle budget, never its pinned hard expiry. There is
one logical interactive operation per client with a ten-minute cap and no
automatic retry of a failed reply or claim. Poll can consume the completed
authorization exactly once, so a lost reply/claim reports `login-unknown`, does
not adopt late access and requires fresh login. Abort and failure use an independent
bounded best-effort `login/cancel`, not logout/session disposal. Replies/attempt
tokens are never serialized, stored, reused for another step or passed to the
renderer. Answers exist only transiently in the current local input/transport;
they are never written to its transcript.

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

`management/version/show` returns the existing native `sys.FormatVersion` output
as `versionInfo: { detail, text }`. Its optional string `long` selector accepts
only `true` (the default) or `false`; it accepts no command, CLI arguments, cursor,
artifact selector or policy override. Loading the version is an explicit action.
The view renders plain text, labels it server-reported metadata rather than an
independent attestation, and clears it on actor changes/logout. It uses the same
connection quota, audit/recording and final-success gate as other metadata reads.

The initial POST endpoints are `management/flows/list`, `management/sessions/list`
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
them. Original artifact streaming uses separate typed endpoints below. The browser
artifact UI uses the portable Go response receiver in a transport worker and the
shared verification/decryption cores in a separate evidence worker. The metadata
JSON adapter alone is not an artifact verifier or a general Go management client.

Tests include shared quota, own logout vs sibling grants, global revocation,
request cancellation, strict final-audit refusal before output, preserved damaged
state, paging and forced-command denial. Actual Go HTTPS/Chromium exercises flow
pagination, session tables/details, cookies/CSP boundaries and actor-changing
reauth with cleared data while the CLI application is deliberately unavailable.

### Forced read ceilings (conservative subset)

The server interprets only the **operator-configured** forced command, never a
browser command. `version`, `version --long`, `version --long=true` and
`version --long=false` retain their exact native long/short output mode. A fixed
short version cannot request long details; no version permission can list flows,
sessions, catalogs, transfer artifacts or mutate sessions. Other recognized forms
are `flow ls`, `audit ls`, `session ls` and `session show` with one exact canonical
session UUID. Supported output flags for these other reads are `--format`
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

`audit ls` permits only the existing four-field summary (name, audit enabled,
recording enabled, encryption configured), including disabled configurations.
These fields match SSH table/JSON/YAML/CBOR without extra projection or a new DTO.
HTTP pagination only partitions the same complete name-ordered summary list;
20-entry/64-KiB/cursor, quota, cancellation, recording and final-audit bounds stay.
No settings, paths, keys, events, producers or recipient details become available.
`includingCredentials` and `allowArtifactTransfer` cannot widen a forced summary
read into another operation. In particular, selecting a row still only chooses
download selectors; recording enumeration, audit/recording downloads and actions
remain denied. Real SSH/HTTP comparisons cover all four formats; actual HTTPS/
Go-WASM-key/Chromium covers 20+2 summary pages, explicit selection, denied transfers
even when transfer is configured, no automatic requests and logout cleanup.

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
integration by themselves. The actual browser artifact view above supplies local
key import, fetch/WASM transport, immutable ReaderAt inputs and full verification/
decryption through the shared Go cores. No CLI arguments become a browser protocol,
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
The browser transport worker uses this receiver; evidence verification remains a
separate operation, not an assertion made by this transport. Browser CLI arguments,
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
EOF and body ownership. The built artifact view and separate browser APIs above
compose this streaming core without treating transport completion as evidence.

### Portable recording evidence verification

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

The separate browser fetch/evidence workers and artifact view above use this
core. Audit now shares its immutable byte/producer-snapshot capability with native
real-file adapters; native filesystem/tree guards are not invented in the browser.
No fake OS/process/filesystem stubs, transport trust pins or second journal
verification implementation substitute for the native proofs.

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

The xterm/fit modules load after confirmed terminal-flow authentication. The UI
opens one shell tab automatically; `+ / New terminal` opens another. Each tab
owns exactly one WebSocket shell with PTY and its own immutable access, renderer
and output. The terminal fills the viewport below the status/tab bar; sign-in
and account settings are dialogs. There is no command/exec or PTY-toggle form
in the UI, while the underlying client/server protocol keeps those capabilities.
No automatic reconnect/reattach or management CLI fallback exists. The proof is
resolved fresh only for the first open message, not stored in the URL,
subprotocol, terminal output or serialized state. Resize, binary/text input,
EOF half-close and INT/TERM requests use the existing strict Go wire contract.
Input is copied/bounded to 64 KiB and paced (4-KiB chunks, conservative 40-KiB/s
budget, small interactive frames no faster than 22 ms, controls at least 100 ms
apart, 16 queued controls). Overflow closes with an explicit error instead of
silently truncating/replaying a paste. Native socket buffering is capped before
more sends, with a five-second blocked-write budget.

The server input buffer has the same 64-KiB byte bound regardless of WebSocket
message size. A fixed ring coalesces small messages while the native backend is
starting instead of counting each keystroke as a separate storage slot. Existing
per-message, message/byte-rate and connection limits remain unchanged. EOF drains
the existing byte stream once; later stdin is rejected, and cancellation unblocks
readers without returning an invented successful execution result.

Decoded output frames are at most 16 KiB, at most 64 jobs/256 KiB may queue behind
one xterm writer, and each renderer job has a five-second budget. The original
UTF-8 byte stream is passed to xterm without per-frame decoding. Final output is
drained before a validated uint32 exit is published. Clean/abnormal close without
an exit is unknown, not status zero. Timers, observers, socket callbacks and
renderer generations are owned/disposed; a tab's renderer is never reused for a
different execution/actor. Scrollback is 1000 lines per tab, with a local limit
of eight tabs independently of the server quotas. Remote
OSC clipboard requests, application-title mutation, window operations and link
activation are not enabled. Theme follows the same computed UI color scheme.

New-access expiry/reauthentication does not replace a running execution. The
terminal keeps its immutable actor-at-start label while a confirmed fresh login
opens a separate new tab. Selecting an existing tab sends no new open request;
closing a live tab requires confirmation and affects only that transport.
Pending/canceled initialization cannot dispatch its old grant later, and dialogs
disable terminal input/focus capture. Explicit logout disconnects owned UI transports
without session disposal or adopting another actor's stored binding. An
uncertain enrollment's original parent is kept for logout/reconciliation instead
of being lost through a new login.

After the current access grant expires, **New terminal** opens the sign-in dialog
without opening a socket; closing that dialog leaves existing shells usable. A
fresh confirmed sign-in opens a new shell, never replaces or reattaches an old one.
Rejected or canceled reauthentication preserves the old grant and tabs, and dialog
input must not enter their terminal streams. A lost logout response leaves local
access blocked and is never reported as confirmed logout or successful process
exit. Only **Retry logout** sends another request; a denied retry is not proof of
server revocation and does not unlock the existing local access.

xterm 6.0.0's documentOverride precedence error requires a version/count-guarded
local bundling correction; see `scripts/README.md`. The supported per-instance
Document adapter nonces style nodes before insertion. No global DOM patch,
unsafe-inline/eval, iframe or upstream build/webpack command is used. The app
component inventory records the modification. Native Go HTTPS/Chromium tests
verify actual xterm I/O, split UTF-8, stderr, resize/signal, post-EOF output,
explicit exit, actor-changing/rejected/canceled reauth, grant expiry, new runs,
abrupt loss, lost logout replies, retained sessions and strict CSP. These UI tests
request shells with PTY; exec/non-PTY coverage belongs to the protocol tests, not
the current UI. The backend is a test hook through the
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
operator HTML and Material UI/Emotion styles. Remote script tags are not granted a nonce;
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
