# xterm document adapter patch

The locked xterm 6.0.0 archive's `src/browser/CoreBrowserTerminal.ts` initializes
`CoreBrowserService` with:

```text
this._document ?? (typeof window !== 'undefined') ? window.document : null
```

Operator precedence selects the global document even when the supported
`documentOverride` is present. In the distributed ESM the exact expression is
`this._document??typeof window<"u"?window.document:null`.

`xterm-document.mjs` changes only that expression to
`this._document??(typeof window<"u"?window.document:null)` during bundling, requiring
exactly one occurrence. It does not edit installed/source packages or relax CSP.
This permits our per-instance `Document` adapter to nonce xterm's style elements
before insertion. Real built-app Chromium tests must remain free of CSP
violations. Remove/review this transformation when changing the locked xterm
version. The app component inventory records the local bundling patch; this is
not a claim of an unchanged upstream binary.

## Release inventory

`browser-release.mjs` inventories the exact generated files, conservative
production npm/Go-WASM/runtime components, lockfiles, applicable project Go
sources, build scripts and local bundling patches. Revision and relevant-input
dirty status are explicit. A normal pinned MISE build creates `browser-build.json`;
an explicit development runtime override does not become release-eligible.
Asset hashes prove only those bytes, npm integrity identifies the locked source
archive, and publisher license supplements prove text only. No signed source
provenance, reproducibility or exact tree-shaken dependency claim is made.
