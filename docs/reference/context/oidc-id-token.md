---
description: How to access context information about a user's ID Token of its successful authorization done via OpenID Connect (OIDC).
---

# Context OpenID Connect (OIDC) ID Token

Holds the ID information about a user who was authorized via [OIDC](../authorization/oidc.md), if configured and available.

## Properties

<<property("issuer", "string")>>

Holds the `iss` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("audience", "string")>>

Holds the `aud` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("subject", "string")>>

Holds the `sub` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("expiry", "datetime")>>

Date when this token will be expired. You will never get a token where this value is in the past.

<<property("issuedAt", "datetime")>>

Holds the `iat` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("nonce", "string", optional=True)>>

**Can** hold the `nonce` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("accessTokenHash", "string", optional=True)>>

**Can** hold the `at_hash` property of the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.2).

<<property("*", "any", optional=True)>>

Any other possible value which was added to the ID Token can be referenced. Like: `idToken.groups` or `idToken.tid`. This depends on the Identity Provider itself, see IdP specific documentation.


