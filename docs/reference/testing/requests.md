---
description: Look up SSH and HTTP test request properties and how requests select configured flows.
---

# Requests {: #request }

A Request describes what someone is asking Bifröst to open. It supplies the
name used by flow requirements and, for HTTP, the server authority and published
slug. It is not an authenticated identity or a network connection.

Use an `object` as [`input.request`](input.md#property-request).

## Properties

<<property("requestingName", "Requesting name", "data-types.md#requesting-name", required=True, heading=3)>>
The requested login name, for example `ops`. It is not automatically the
authenticated account or the target user.

<<property("transport", "Transport", "data-types.md#transport", default="ssh", heading=3)>>
The logical transport whose flow-selection rules should be used.

<<property("method", "Authentication method", "data-types.md#authentication-method", default="password", heading=3)>>
The authentication method whose configured rules should be used. The supported
combinations are [listed below](#authentication-methods). An explicit empty
string also uses `password`; it does not enable OIDC.

<<property("host", "Server authority", "data-types.md#server-authority", optional=True, heading=3)>>
**Required for HTTP; not accepted for SSH.** The Bifröst server authority.
Supply it explicitly; there is no separate origin override.

<<property("slug", "Slug", "data-types.md#slug", optional=True, heading=3)>>
**Required for HTTP; not accepted for SSH.** The requested published flow path.
Use `""` explicitly for the root.

## Examples

### SSH

Use this object as `input.request`:

```lua
local request = object { requestingName = "ops" }
```

### HTTP

```lua
local request = object {
  transport = "http",
  requestingName = "ops",
  method = "oidc",
  host = "APP.Example.Org.:08443",
  slug = "servers/Work",
}
```

This describes a request to the HTTPS endpoint `app.example.org:8443`; it does
not send an HTTP request. For the service's real endpoint behavior, see
[HTTP connections](../connection/http/index.md).

## Authentication methods {: #authentication-methods }

| Method | SSH | HTTP |
| --- | --- | --- |
| `password` | Local assumptions; OIDC rejects this method. | Local assumptions; OIDC rejects this method. |
| `keyboard-interactive` | Local or either OIDC grant. | Device Authorization or an eligible local interactive method, not Code Grant. |
| `oidc` | Unsupported input (error). | Code Grant, when the configured callback origin matches the request origin. |

Method eligibility still follows configuration and binary capabilities,
including whether local interaction/PAM is available. A local assumption does
not bypass those method-selection rules or run a native login.

If a method is ineligible, that flow's assumed result is not consumed. For
example, a password request does not use an OIDC `allow`. Another eligible flow
may be tried according to normal matching rules.

## Canonical request values {: #canonical-result }

Your original values remain in `t.input.request`. `actual.request` shows the
values used after matching normalization. In the HTTP example above:

| Result field | Value |
| --- | --- |
| `actual.request.host` | `app.example.org` |
| `actual.request.origin` | `https://app.example.org:8443` |
| `actual.request.slug` | `servers/Work` |

Origin is derived from authority. Host casing, IDNA, trailing DNS dots, IPv6
spelling, numeric port aliases and the default HTTPS port are canonicalized.
Invalid authorities, slugs and encodings fail before an authentication outcome
is used. Server authority does not supply `.remote.host` in policy templates.

See [Request result properties](result.md#request) for the returned data type.

## Matching and published flows

Requests use the same [flow requirements](../flow.md#requirement), ordering and
transport switches as the service. HTTP `requestUser: true` requires a
non-whitespace name; `false` requires exactly `""`. Requirements still apply to
nameless requests.

On a matching canonical host, a flow's `discoverAsSlug` fixes the request's
published assignment. Failed requirements, incompatible name/method/origin,
denial or error do not redirect that assignment to a generic flow. Root and
valid unpublished slugs use ordinary configuration-order matching, denial
fallback and error abort. Case-distinct slugs are not aliases.

The HTTP endpoint is assumed to have accepted the request. TLS/domain/browser
checks are outside [the testing scope](index.md#scope). See the
<<asset_link("pkg/test/examples/http/README.md", "HTTP examples")>> for complete suites.
