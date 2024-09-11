---
description: How to access context information about an user's token of its successful authorization done via OpenID Connect (OIDC).
---

# Context OpenID Connect (OIDC) Token

Holds the main information about a user who was authorized via [OIDC](../authorization/oidc.md).

## Properties

<<property("accessToken", "string")>>

Contains the `access_token` as defined via [RFC](https://openid.net/specs/openid-connect-basic-1_0.html).

<<property("tokenType", "string")>>

Contains the `token_type` as defined via [RFC](https://openid.net/specs/openid-connect-basic-1_0.html).

<<property("refreshToken", "string", optional=True)>>

**Can** contain the `refresh_token` as defined via [RFC](https://openid.net/specs/openid-connect-basic-1_0.html).

<<property("expiry", "datetime", optional=True)>>

**Can** contain the `expires_in` as defined via [RFC](https://openid.net/specs/openid-connect-basic-1_0.html).
