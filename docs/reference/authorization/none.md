---
toc_depth: 4
description: How to enable users to access Bifröst without any kind of password or SSH key.
---

# None authorization

Always authorizes a user regardless of the password used, even if no password or SSH key is provided.

!!! danger
     This authorization enables a high security risk.

      There are only very rare cases where this makes sense. Only in cases like creating a demo server does it make sense to use it. See [our demonstration/training use case as a ligable example](../../usecases.md#demos)

     A macOS local environment rejects `none` authorization by default. Its [`targetAccountPolicy.allowUnsafeNoneAuthorization`](../environment/local.md#targetAccountPolicy-property-allowUnsafeNoneAuthorization) override removes that safeguard and can turn an unauthenticated SSH connection into local account access. Do not enable it on a host environment; if a controlled test requires it, also constrain the target with explicit account allowlists.

## Properties

_None._

## Context

This authorization will produce a context of type [Authorization Simple](../context/authorization.md#simple).

## Examples

```yaml
type: none
```

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
