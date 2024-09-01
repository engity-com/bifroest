---
description: How to access context information about an user's UserInfo of its successful authorization done via OpenID Connect (OIDC).
---

# Context OpenID Connect (OIDC) UserInfo

Holds the full user information about a user who was authorized via [OIDC](../authorization/oidc.md), if configured and available.

## Properties

<<property("subject", "string")>>

Subject - Identifier for the End-User at the Issuer (see [spec](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5) for more details).

<<property("profile", "string", optional=True)>>

RL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User (see [spec](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5) for more details).

<<property("email", "email", optional=True)>>

End-User's preferred e-mail address (see [spec](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5) for more details).

<<property("emailVerified", "bool", optional=True)>>

True if the End-User's e-mail address has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating (see [spec](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5) for more details).
