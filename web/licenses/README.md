# License-text supplements

`react-remove-scroll-bar@2.3.8` declares MIT in its npm metadata/archive but omits
the license file. The checked-in text is the publisher repository's MIT notice:

https://raw.githubusercontent.com/theKashey/react-remove-scroll-bar/8ca9ba5ea52de03308fe8ced94f7b159a44d28ff/LICENSE

The version-specific provenance bridge is recorded in
[`react-remove-scroll-bar-2.3.8-evidence.json`](react-remove-scroll-bar-2.3.8-evidence.json):

- Both publisher npm archives declare MIT and were checked against their npm
  SHA-512 integrities. All 26 files other than the root `package.json` are
  byte-identical between 2.3.7 and 2.3.8, including all executable distributions.
- The only package metadata changes are the version and the minimum
  `react-style-singleton` range (`^2.2.1` to `^2.2.2`). Dependencies retain their
  own locked license notices; this comparison does not exempt that change.
- The publisher's retrievable 2.3.7 gitHead is
  `29e9fcd1eecf7d3b77a767941c4a57fe461fc1e4`. Comparing it with the pinned license
  source commit above changes **only `LICENSE`**; the source files are unchanged.
- An offline test checks the installed 2.3.8 payload hashes, lock integrity and
  supplement text against this recorded bridge. No build downloads are added.

This strengthens the provenance of the publisher's MIT notice for the unchanged
package payload. It is **not** a reproducible TypeScript-source/tarball match or
a legal opinion: 2.3.8 gitHead `b3b1287aad81def2e2ae707274b74531b61ddbaf` remains
unretrievable. Package version and integrity remain locked separately. Future
versions without license text require their own review. Release notices/SBOMs
preserve the caveat; browser inventory is unsigned build metadata, not an
exact-source attestation.
