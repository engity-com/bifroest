# Logical HTTP examples

From the repository root:

```text
bifroest test pkg/test/examples/http --verbose
```

Seven tests cover named/nameless Code Grant results, canonical HTTPS origins,
published-flow pinning across method/port/name-mode mismatches and denial, and
an unpublished root request using Device Authorization.

`request.host` is the server authority, not a URL or remote peer. HTTP requires
explicit `slug` and `requestingName`, including empty strings for root/nameless
mode. `t.input` keeps original values; `actual.request` shows canonical selection.

The endpoint and authentication are assumed. No listener, TLS/domain/Origin-header
check, HTTP routing, browser/IdP exchange, session or target process is exercised.

See the [request reference](../../../../docs/reference/testing/requests.md),
[scope and limitations](../../../../docs/reference/testing/index.md),
[CLI reference](../../../../docs/reference/cli/test.md) and
[other examples](../../README.md).
