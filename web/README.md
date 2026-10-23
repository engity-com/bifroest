# Browser client core

This is the first independently testable browser RememberMe storage/signing core,
not the React/Mantine UI or a connected HTTP login client. Go does not serve or
embed these resources yet. Vite 8/Rolldown builds the dependency-free core; there
is no Webpack or production Node runtime.

Use Node 24.14 or newer and this repository's Go toolchain for the native proof
interoperability test. From `web/` (also native Windows/Nushell compatible):

```text
npm ci --ignore-scripts
npm run check
npm run test:browser:install
npm test
npm run build
```

Tests run in actual headless Chromium, including real IndexedDB structured cloning
of non-exportable CryptoKeys and an actual browser-process restart using an owned
temporary profile. The test fixture uses a secure-context loopback HTTP origin;
the real Go proof core supplies and verifies a challenge signed by the restarted
browser client's persisted key. Its native helper is test-only, never a web-action
or production CLI subprocess. This is not production HTTPS/login/UI coverage.
Browser installation is an explicit development/test
step and does not change the OS/browser trust store. Build output goes to the
ignored `var/webui-client-build/` directory; dependencies and compiler versions are
locked. React/Mantine, xterm, production asset serving and release/SBOM integration
remain subsequent steps.

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
