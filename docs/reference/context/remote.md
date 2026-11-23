---
description: How to access context information about a remote user data within Bifröst.
---

# Context Remote

Represents a user who is connected to Bifröst.

## Properties

<<property("host", "Host", "../data-type.md#host")>>

Numeric client IP address, without a port, of the incoming connection. Direct HTTP uses the socket peer; explicit [reverse-proxy mode](../connection/http/index.md#upstream-forwarded-headers) uses the validated `X-Forwarded-For` chain. This is not HTTP host selection; that is `.connection.http.host`. Native SSH peer handling is unchanged.

<<property("user", "string")>>

Original username supplied by the requesting client, for example `foo@bar` in
`ssh -l 'foo@bar' bifroest.example.org`. It remains unchanged by authorization's
`remoteName` mapping and is not proof of an authenticated principal.
