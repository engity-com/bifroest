---
description: Shared value types used by Lua test declarations, input and results.
toc_depth: 2
---

# Data types

These types describe values used by the [Lua API](lua.md), not classes to
instantiate. Object properties are documented on their owning reference pages.
Schema property names must use the exact documented spelling, including case;
aliases such as `UID` for `uid` are rejected. Flow names and arbitrary OIDC claim
and OAuth extra keys remain data keys, not schema properties.
General Bifröst types, such as [Flow Name](../data-type.md#flow-name), retain
their normal meaning; a testing Name is a different type.

Fixture strings and object keys must be valid UTF-8. Malformed byte sequences
are rejected before JSON conversion, not replaced or normalized. Valid Unicode,
including an explicitly supplied replacement character (`�`), is preserved.

## Architecture selector {: #architecture-selector }

A case-sensitive binary architecture identifier, such as `amd64`, `arm64` or
`armv7`. Its string form matches `[a-z0-9][a-z0-9_-]{0,31}`.
It selects the Bifröst binary, not the target or SSH client architecture.

## Authentication method {: #authentication-method }

A string selecting the authentication path: `password`, `keyboard-interactive`
or `oidc`. The permitted transport/authorizer combinations are documented under
[request method eligibility](requests.md#authentication-methods).

An omitted or explicitly empty request method uses `password`. That default
does not enable OIDC. The calculated result always contains the effective method.

## Authentication mode {: #authentication-mode }

A string describing how an authentication assumption supplies an identity:

| Value | Meaning |
| --- | --- |
| `post-authentication` | Local authentication has already resolved the supplied account. |
| `mapped-local` | Evaluate the configured local `remoteName`, then bind that account. |
| `verified-oidc` | Use an explicitly supplied OIDC identity; verification is assumed. |

Local assumptions default to `post-authentication`. Successful OIDC assumptions
must explicitly select `verified-oidc`. Results contain the effective mode.
See [test input](input.md#property-authentication) for the corresponding data.

## Authentication outcome {: #authentication-outcome }

`allow` assumes authentication succeeded; `deny` assumes it failed. This string
is an input observation, not the expected overall [Decision](#decision).
Even after `allow`, flow matching, identity mapping and target rules must succeed.

## Data value {: #data-value }

| Type | Meaning and example |
| --- | --- |
| `string` | Text, such as `"alice"`. |
| `bool` | `true` or `false`. |
| `integer` | A whole-number Lua value, such as `1001`. |
| `float` | A floating-point Lua value, such as `1.0`; distinct from an integer in assertions. |
| [Object](lua.md#function-object) | Named fields created with `object { ... }`. |
| `[]T` | Ordered items of type `T`, created with [`list { ... }`](lua.md#function-list). |
| [null](lua.md#null) | Explicit absence, only where permitted. |

For example, `[]Account` means a list of the [Account](local.md#account) objects
documented in this reference. Values received through [the test context](context.md)
and [results](result.md) use the same vocabulary and are read-only.

Lua `nil` is not an object field value: it omits the field. It can still be
compared by `IsEqual`, for example after an out-of-range list read. It is
distinct from explicit `null`. Ordinary Lua tables can build declarations and
generate cases; use `object`/`list` for fixture data and composite assertions so
their intended shape is explicit.

## Decision {: #decision }

A calculated result string: `selected` when the supported selection steps
succeeded, otherwise `deny`. There is no `allow` decision. Selection is not a
login or complete access authorization; see [scope](index.md#scope).

## Name {: #name }

A suite or test name, represented as a case-sensitive string of 1–80 Unicode
code points. It accepts printable letters, numbers and combining marks, plus
exactly `.,-_[]()%@!~=+`.

Whitespace, separators, quotes, controls, invisible format/default-ignorable
characters, variation selectors, emoji and other symbols are rejected. Names
are not Unicode-normalized or silently rewritten.

Examples: `access`, `ops-selects-target`, `team[1]`. The slash in `access/ops`
separates two Names; it cannot be part of either Name. This type does not apply
to configured flow names or account names.

Qualified `suite/test` names must be unique across platform-matching suites;
mutually exclusive platform variants may share names. Filters use regular
expressions, so escape metacharacters when matching names literally.

## OS selector {: #os-selector }

A case-sensitive binary operating-system identifier, such as `linux`, `darwin`
or `windows`. Its string form matches `[a-z0-9][a-z0-9_-]{0,31}`.
The selector-only group `unix` means exactly Linux and macOS.
It selects the Bifröst binary and does not emulate another OS.

## Requesting name {: #requesting-name }

The requested login name as a UTF-8 string, unchanged by matching. This is not
a suite/test [Name](#name), an authenticated identity or a target account.

- SSH: nonempty, not all whitespace, at most 128 bytes, without control characters.
- HTTP: at most 256 bytes, without control characters. Nameless mode uses `""`
  explicitly; the configured flow's `requestUser` rule determines whether a
  name is required.

Missing/null is not an empty name. Names are not trimmed.

## Server authority {: #server-authority }

A server host with an optional numeric port, represented as a string such as
`app.example.org:8443` or `[2001:db8::1]:8443`. Ports range from 1 to 65,535;
IPv6 addresses require brackets. A scheme, user information, path, query or
fragment is not accepted. This is an authority, not a URL or the remote client's host.

See [request normalization](requests.md#canonical-result) for canonical host
and HTTPS origin values. An omitted port means the default HTTPS port, 443.

## SID {: #sid }

A canonically spelled Windows security identifier, represented as a string,
for example `S-1-5-21-1-2-3-1001`. Account and group facts must use their actual
respective identifiers within the fixture; display names are not SID aliases.
Supplying a SID does not query or create a Windows account or group.

## Slug {: #slug }

A case-sensitive string: `""` for the root, or one/two segments separated by
`/`, for example `Work` or `servers/Work`. Each segment contains 1–64 ASCII
letters, digits or hyphens. The exact first segments `login`, `assets` and `api`
are reserved. Leading/trailing slashes, empty segments and URL-encoded aliases
are not accepted; the value is not URL-decoded.

## Transport {: #transport }

The request transport string: `ssh` or `http`. An omitted transport uses `ssh`;
other values, including an explicitly empty string, are errors.

## Unix ID {: #unix-id }

A Lua integer in the range 0–4,294,967,295, used for a Unix UID or GID.
A float such as `1001.0` is not an integer ID. Windows SIDs are a separate type.

## UTC timestamp {: #utc-timestamp }

A string in RFC 3339 UTC form ending in `Z`, for example
`"2030-01-01T00:00:00Z"`. Non-UTC spellings are rejected. Raw OIDC `exp`/`iat`
claims, when included, are interpreted as whole Unix seconds. The resulting
instants must exactly match the metadata timestamps; matching only the seconds
component of a fractional metadata timestamp is not enough.

## Version selector {: #version-selector }

A string matching the Bifröst binary's version:

| Form | Matches |
| --- | --- |
| Complete SemVer, optionally prefixed with lowercase `v` | Exact version including prerelease identity; build metadata does not affect equality. |
| `1` or `1.2` | Stable versions in that major/minor series, not prereleases. |
| `[1.3.5,1.4.0)` | Interval: square endpoints include, round endpoints exclude. One bound may be omitted with an open endpoint, e.g. `(,1.4.0]`. Bounds must be complete SemVer. |
| `development` or another non-SemVer label | Exact case-sensitive full string, without trimming or wildcards. Never matches a SemVer entry. |

Empty/reversed intervals are invalid. Prereleases match an interval only when
at least one bound contains a prerelease and the comparisons match. A string
starting with `[` or `(` must be a valid interval, not an arbitrary label.
Each selector is nonempty and at most 256 bytes.
