# Installed curl transport probes

Use a current, security-maintained curl package. The versions below describe tested or expected functionality, not a recommendation to install an old release.

## Run

Requires Go and curl on PATH; no Bifröst build, root privileges, container runtime or Internet access is needed. The servers listen on loopback and use a temporary CA for TLS verification.

```sh
mise run test:e2e:curl
```

Alternatively, run `go test -v -count=1 -tags=e2e -timeout=2m ./test/curl`. The suite also runs as part of `mise run test:e2e`. On WSL with interop, it discovers and runs both `curl` and `curl.exe`.

## Tested versions

Recorded probe results on 2026-11-20:

| Client | TLS backend | HTTP/1.1 streaming (`http1`, `https1`) | HTTPS over HTTP/2 (`https2`) | WebSocket streaming with empty Close (`ws-empty-close`, `wss-empty-close`) |
| --- | --- | --- | --- | --- |
| Linux curl 8.18.0 | OpenSSL 3.5.9 | Passed | Passed | Passed |
| Windows curl.exe 8.22.0 | Schannel | Passed | Not included in this build | Alternating transfers passed; concurrent duplex fails — unsuitable as an SSH WSS proxy |

These results apply to the tested binaries, not every build with the same version number. The Windows client ran natively through WSL interop against Linux test servers. macOS has not been tested natively.

Both clients also transferred WebSocket data with a normal Close status of `1000`, but appended its two bytes (`03e8`) to stdout. Those `ws` and `wss` profiles therefore failed the exact-byte-stream check. The empty-Close profiles passed without stdout filtering.

The probes cover server-first output, transfers above 3 MiB, simultaneous send/receive and clean termination. Independent reference clients, buffering/corruption controls and certificate rejection checks validate the fixture. The concurrent WSS test exposes corruption not detected by alternating exchanges. The production SSH E2E reproduces this with Windows curl 8.22.0/Schannel as an SSH MAC failure; use HTTPS/1.1 with that build. Reachability through a particular firewall is not established by these tests.

## Probably working versions — not verified

| Transport | Expected baseline across Linux, macOS and Windows | Basis |
| --- | --- | --- |
| HTTP/1.1 streaming | curl 8.15.0 or newer, built with HTTPS support | [8.15.0](https://curl.se/ch/8.15.0.html) added nonblocking stdin on Windows and improved nonblocking stdin performance. |
| WS/WSS streaming with empty Close | curl 8.16.0 or newer, built with WS/WSS support | [8.16.0](https://curl.se/ch/8.16.0.html) added the read-callback support needed for command-line WebSocket uploads. |

These are conservative, likely usable baselines based on upstream changes, not tested minimum versions or a guarantee for every later build. Older Linux/macOS versions may also work; no historical minimum is claimed. Build options, vendor patches and regressions can affect functionality. Prefer updating curl over depending on an untested older version.

## Result policy

Every discovered client must pass `http1` and `https1` by default. Other profiles are capability discovery: unsuccessful profiles are explicitly reported as **UNSUITABLE / SKIP**, not as working transports. A passing suite does not mean every profile works.

| Environment variable | Meaning |
| --- | --- |
| `BIFROEST_TEST_CURL` | Executable name or path; replaces automatic discovery. |
| `BIFROEST_TEST_CURL_REQUIRE` | Comma-separated required profiles; replaces the default `http1,https1`. |

Available profiles are `http1`, `https1`, `https2`, `ws`, `wss`, `ws-empty-close` and `wss-empty-close`. `all` requires every profile; `none` only reports transport capabilities. Reference, negative-control and certificate checks remain mandatory. Invalid profile names and missing curl installations fail immediately.
