---
description: How to access core context information within Bifröst.
---

# Context Core

Represents the core of Bifröst.

## Properties

This context does not provide any kind of properties; but all functions can be used.

It has no current connection. Connection-bound request and environment contexts
separately expose [`.connection`](connection.md); startup and background contexts
must not fabricate SSH/HTTP metadata to imitate them.
