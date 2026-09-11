---
description: How to access context information about an authorized user with Bifröst.
---

# Context Authorization

Represents a fully authorized connection of a user.

There are more specialized variants of the authorization available, based on which authorization type was used:

| Variant                        | Authorization                                     |
|--------------------------------|---------------------------------------------------|
| [Bifröst](#bifroest)           | [Bifröst delegation](../authorization/bifroest.md) |
| [Htpasswd](#htpasswd)          | [Htpasswd](../authorization/htpasswd.md)          |
| [Local](#local)                | [Local](../authorization/local.md)                |
| [OpenID Connect (OIDC)](#oidc) | [OpenID Connect (OIDC)](../authorization/oidc.md) |
| [Simple](#simple)              | [Simple](../authorization/simple.md)              |
| [None](#none)                  | [None](../authorization/none.md)                  |

## Bifröst {: #bifroest}

Is the result of a successful certificate-based delegation from another [Bifröst authorization](../authorization/bifroest.md). The common authorization `remote` remains the immediately connected SSH peer; use `origin` for the unchanged original identity.

### Properties

<<property("origin", "object", id_prefix="bifroest-", heading=4)>>
The original `user`, `host` and `authorizationKind` from the first Bifröst instance.

<<property("peer", "object", id_prefix="bifroest-", heading=4)>>
The final, immediately verified hop. It contains the CA and subject-key fingerprints, serial, key ID, upstream session ID and flow, authorization kind, audience, target user, validity boundaries, and effective capability booleans.

<<property("hops", "list of objects", id_prefix="bifroest-", heading=4)>>
The complete normalized delegation path. Each object has the same fields as `peer`. The list has at most eight entries.

<<property("policy", "object", id_prefix="bifroest-", heading=4)>>
The effective `ptyAllowed`, `portForwardingAllowed` and `agentForwardingAllowed` values after all hops.

Passwords, tokens, unrestricted identity-provider claims and arbitrary environment maps are never included in this context.

## Htpasswd

Is the result of a successful authorization via [Htpasswd authorization](../authorization/htpasswd.md).

### Properties

<<property("user", "string", id_prefix="htpasswd-", heading=4)>>

Holds the user(name) of the successfully authorized user.

## Local

Is the result of a successful authorization via [Local authorization](../authorization/local.md).

### Properties

<<property("user", "Local User", "local-user.md", id_prefix="local-", heading=4)>>

Holds the successfully authorized user.

## OpenID Connect (OIDC) {: #oidc}

Is the result of a successful authorization via [OpenID Connect (OIDC) authorization](../authorization/oidc.md).

### Properties

<<property("token", "OIDC Token", "oidc-token.md", id_prefix="oidc-", heading=4)>>

Holds the token information (like [access token](https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.1.2), expiry, ...) of the authorized user.

<<property("idToken", "OIDC ID Token", "oidc-id-token.md", id_prefix="oidc-", heading=4, optional=True)>>

**Can** hold the [ID Token](https://openid.net/specs/openid-connect-basic-1_0.html#IDToken) of the authorized user, if configured and available.

<<property("userInfo", "OIDC UserInfo", "oidc-user-info.md", id_prefix="oidc-", heading=4, optional=True)>>

**Can** hold the [UserInfo](https://openid.net/specs/openid-connect-basic-1_0.html#UserInfo) of the authorized user, if configured and available.

## Simple

Is the result of a successful authorization via [Simple authorization](../authorization/simple.md).

### Properties

<<property("entry", "Simple Entry", "simple-entry.md", id_prefix="simple-", heading=4)>>

Holds a representation of the authorized record of [Simple authorization entries](../authorization/simple.md#property-entries).

## None

Is the result of a successful authorization via [None authorization](../authorization/none.md).

### Properties

_None._
