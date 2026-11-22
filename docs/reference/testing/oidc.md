---
description: Properties of an assumed OIDC identity, including OAuth token, ID token and UserInfo data.
---

# OIDC data {: #oidc }

An OIDC test supplies the identity and data that authentication should be
assumed to have returned. You can then test rules such as principal mapping
from `preferred_username`. You do not supply a signed token or contact an IdP.

Use this object as the `oidc` property of a successful
[authentication assumption](input.md#authentication), with
`mode = "verified-oidc"`. The name means **verification is assumed**, not
performed by the test runner. Token, ID token and UserInfo are independent:
no data is copied between them or inferred from the requesting name.

See [OIDC authorization](../authorization/oidc/index.md) for product configuration
and [request methods](requests.md#authentication-methods) for SSH/HTTP eligibility.

## Properties

<<property("issuer", "URL", "../data-type.md#url", required=True, heading=3)>>
The HTTPS issuer. It must exactly match the configured flow's issuer after
supported template evaluation. An unrelated issuer is an error.

<<property("subject", "string", required=True, heading=3)>>
The assumed authenticated subject (`sub`). This starts as the identity's
principal; configured principal mapping can change the principal, not this subject.

<<property("token", "OAuth token or null", "#token", optional=True, heading=3)>>
The OAuth token data. Supply an object when the rule needs token fields, or
`null` for known absence. If omitted, token data is unknown and errors when read.

<<property("idToken", "ID token or null", "#id-token", optional=True, heading=3)>>
The verified ID-token data to assume. When `retrieveIdToken` is enabled, the
observation must be supplied even if principal mapping does not read it.
See [visibility and absence](#visibility) for when `null` is accepted.

<<property("userInfo", "UserInfo or null", "#user-info", optional=True, heading=3)>>
The UserInfo data to assume. Enabled `retrieveUserInfo` requires an object:
`null` is not a successful retrieval. With retrieval disabled, omission can
leave this data unknown.

## OAuth token {: #token }
<span id="artifacts"></span>

If an object is supplied, all properties below are required, including empty
strings or an empty `extra` object where appropriate. This is a data record,
not an encoded token. For policy access, see [OIDC Token context](../context/oidc-token.md).

<<property("accessToken", "string", required=True, id_prefix="token-", heading=3)>>
Synthetic access-token value.

<<property("tokenType", "string", required=True, id_prefix="token-", heading=3)>>
Token type, for example `Bearer`.

<<property("refreshToken", "string", required=True, id_prefix="token-", heading=3)>>
Synthetic refresh-token value; use `""` when empty. No refresh is performed.

<<property("expiry", "UTC timestamp", "data-types.md#utc-timestamp", required=True, id_prefix="token-", heading=3)>>
Assumed expiry metadata. It is not checked as proof of token validity.

<<property("extra", "Object", "lua.md#function-object", required=True, id_prefix="token-", heading=3)>>
Complete OAuth extra fields. Missing keys have the product's absent-value
behavior rather than being invented. Use `object {}` for no extra fields.

## ID token {: #id-token }

All properties below are required when an object is supplied. The data describes
an assumed verified token, not a JWT to verify. Policy access follows the
[OIDC ID Token context](../context/oidc-id-token.md).

<<property("issuer", "URL", "../data-type.md#url", required=True, id_prefix="id-token-", heading=3)>>
Must agree with the OIDC identity's `issuer`.

<<property("subject", "string", required=True, id_prefix="id-token-", heading=3)>>
Must agree with the OIDC identity's `subject`.

<<property("audience", array_ref("string"), required=True, id_prefix="id-token-", heading=3)>>
The assumed audience list. Supplying it does not verify an actual token's audience.

<<property("expiry", "UTC timestamp", "data-types.md#utc-timestamp", required=True, id_prefix="id-token-", heading=3)>>
Assumed expiry time.

<<property("issuedAt", "UTC timestamp", "data-types.md#utc-timestamp", required=True, id_prefix="id-token-", heading=3)>>
Assumed issue time.

<<property("nonce", "string", required=True, id_prefix="id-token-", heading=3)>>
Nonce metadata; supply `""` explicitly when empty.

<<property("accessTokenHash", "string", required=True, id_prefix="id-token-", heading=3)>>
Access-token hash metadata; supply `""` explicitly when empty.

<<property("claims", "Object", "lua.md#function-object", required=True, id_prefix="id-token-", heading=3)>>
The complete claims map. For example, a `preferred_username` claim can be used
by the configured principal template. Use `object {}` when no raw claims are needed.

## UserInfo {: #user-info }

All properties below are required when an object is supplied. See
[OIDC User Info context](../context/oidc-user-info.md) for policy access.

<<property("subject", "string", required=True, id_prefix="user-info-", heading=3)>>
Must agree with the OIDC identity's `subject`.

<<property("profile", "string", required=True, id_prefix="user-info-", heading=3)>>
Profile value; supply `""` explicitly when empty.

<<property("email", "string", required=True, id_prefix="user-info-", heading=3)>>
Email value; supply `""` explicitly when empty.

<<property("emailVerified", "bool", required=True, id_prefix="user-info-", heading=3)>>
Assumed email-verification state. `false` is a value, not an omitted observation.

<<property("claims", "Object", "lua.md#function-object", required=True, id_prefix="user-info-", heading=3)>>
The complete UserInfo claims map, separate from ID-token claims.

## Example

This is a **value for `input.authentication`**, not a complete suite. It assumes
the configured flow is named `primary`, uses the issuer below and enables
`retrieveIdToken` while disabling `retrieveUserInfo`:

```lua
local authentication = object {
  primary = object {
    outcome = "allow",
    mode = "verified-oidc",
    oidc = object {
      issuer = "https://issuer.example.org",
      subject = "id-123",
      token = null,
      idToken = object {
        issuer = "https://issuer.example.org",
        subject = "id-123",
        audience = list { "example-client" },
        expiry = "2030-01-01T00:00:00Z",
        issuedAt = "2020-01-01T00:00:00Z",
        nonce = "",
        accessTokenHash = "",
        claims = object { preferred_username = "alice" },
      },
    },
  },
}
```

For a complete runnable configuration and suite, see the
<<asset_link("pkg/test/examples/oidc/README.md", "OIDC examples")>>.

## Visibility and absence {: #visibility }

The product's `retrieveIdToken`/`retrieveUserInfo` settings determine which data
configuration templates can read. Supplying a hidden record does not make it
visible. Hiding a record does not change the authenticated issuer or subject.

`null` for an ID token is permitted with refresh enabled, but fails when
`retrieveIdToken` is true and both refresh and forced-disposal verification are
disabled. UserInfo retrieval always needs an object when enabled. An absent
OAuth token is known absent; its token fields have no value in policy templates.

The result exposes the [identity and authentication binding](result.md#authentication),
not token/claim dumps. Principal mapping changes only the principal.

## Consistent values and types

Metadata and any duplicate standard claims must agree. For example, a raw
`sub` claim cannot contradict `subject`, even when the record is hidden.
Do not duplicate standard claims unless your test needs them.

Claims and extra fields use the same JSON-derived types as production policy
templates. In particular, numeric claims are floating-point values: compare
them with `1.0`, not integer `1`, in a Go template. This does not change the
integer/float distinction in the original Lua input. Canonical metadata and
aliases such as `accessToken`/`access_token` follow the linked context references.

## Timestamps in templates {: #timestamp }

Metadata times use the [UTC timestamp](data-types.md#utc-timestamp) type.
Configuration templates receive time values with the supplied UTC zone.
Host-local formatting is not reproduced. Time method chains such as
`.expiry.Local` or `.issuedAt.Location` are unsupported. Read specific data
fields, not entire token objects; see [template limits](isolation.md#templates).
