# Browser application and client core

The first React 19/Mantine 9 application supports password login, explicit
RememberMe opt-in, saved-access resumption, confirmed logout/revocation and
explicit local-only recovery. It uses en-US message keys and memory-only
auto/light/dark appearance. Terminal UI, interactive/OIDC/key-login dialogs,
imported keys and structured Management remain incomplete. Vite 8/Oxc/Rolldown
builds the application and the independently tested, dependency-free HTTP/crypto
core; there is no Webpack/Babel chain or production Node runtime.

Use Node 24.14 or newer and this repository's Go toolchain for the native proof
interoperability test. From `web/` (also native Windows/Nushell compatible):

```text
npm ci --ignore-scripts
npm run check
npm run test:browser:install
npm test
npm run build
```

`build:core` writes `var/webui-client-build/`; `build:app` writes generated files
to `pkg/webui/assets/` before Go embeds them. Generated bundles are ignored;
only the source marker is tracked. Run the frontend build **before** building
the Go binary. A source-only Go checkout still compiles for SSH/API development,
but has no embedded UI until these resources are built. An `assetsDirectory`
containing a complete app can also supply the UI. Full release-job preparation,
aggregate SBOM/provenance integration and the remaining feature work are not done.

The optional real HTTPS/client/WebSocket test additionally uses the Go service
fixtures. After building, run the following from the repository root with
`BIFROEST_TEST_BROWSER_CLIENT=1` and, if necessary, `BIFROEST_TEST_NODE` pointing at
the selected Node executable (set these through your native shell's environment):

```text
go test -race ./pkg/service -run '^TestBrowserRememberMeClientAgainstRealHttpsAndWebSocket$' -count=1 -timeout=90s
```

Set `BIFROEST_TEST_BROWSER_UI=1` for real UI/CSP/recovery tests and run
`go test -race ./pkg/service -run '^TestBrowserLoginUi' -count=1 -timeout=90s`.
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
overlays and ordered local customization. Xterm, remaining dialogs/Management and
complete release/SBOM integration remain subsequent steps.

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
reconciled. Interactive/OIDC/key-login dialogs, terminal UI and Management remain
subsequent work.

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
