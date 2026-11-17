---
description: How to access context information about a remote user data within Bifröst.
---

# Context Remote

Represents a user who is connected to Bifröst.

## Properties

<<property("host", "Host", "../data-type.md#host")>>

Direct numeric peer IP address, without a port, of the incoming connection. For
HTTP, this does not come from `Forwarded` or `X-Forwarded-*` headers and is not the HTTP host
selection; that is `.connection.http.host`.

<<property("user", "string")>>

Original username supplied by the requesting client, for example `foo@bar` in
`ssh -l 'foo@bar' bifroest.example.org`. It remains unchanged by authorization's
`remoteName` mapping and is not proof of an authenticated principal.
