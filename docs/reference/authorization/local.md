---
toc_depth: 4
description: How to authorize a requesting user via the local user database of the host on which Bifröst is running on.
---
# Local authorization

Authorizes a requesting user via the local user database of the host on which Bifröst is running on.

!!! note
    This authorization requires Bifröst to run with root permissions.

## Properties

<<property("type", "Authorization Type", default="local", required=True)>>
Has to be set to `local` to enable the local authorization.

<<property_with_holder("authorizedKeys", "Array", None, "Authorized Keys", "../data-type.md#authorized-keys", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files of the format of classic [authorized keys](../data-type.md#authorized-keys) Bifröst will look in for [SSH Public Keys](../data-type.md#ssh-public-key) .

<<property("password", "Password", "#password")>>
Contains files of the format of classic [authorized keys](../data-type.md#authorized-keys) Bifröst will look in for [SSH Public Keys](../data-type.md#ssh-public-key) .

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be used during the authorization process instead of `/etc/passwd` and `/etc/shadow` directly.

##### Default settings

| [`linux`/`extended`](../../setup/distribution.md#linux-extended) | anything else |
| - | - |
| `sshd` | _empty_ |

## Password

The password can either be validated via `/etc/passwd` and `/etc/shadow` (default) or via PAM (if [`pamService`](#property-pamService) is set to a valid value).

### Support of yescrypt {. #password-yescrypt}

[yescrypt](https://en.wikipedia.org/wiki/Yescrypt) is cryptographic key derivation function used for password hashing in some modern Linux distributions (such as Ubuntu). Their support and give Bifröst the possibility to evaluate their passwords, the [`linux`/`extended` edition](../../setup/distribution.md#linux-extended) of Bifröst is required.

### Properties {. #password-properties}

<<property_with_holder("allowed", "Bool Template", "../templating/index.md#bool", "Context Password Authorization Request", "../context/authorization-request.md#password", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via classic password authentication

<<property_with_holder("interactiveAllowed", "Bool Template", "../templating/index.md#bool", "Context Interactive Authorization Request", "../context/authorization-request.md#interactive", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via interactive authentication.

<<property_with_holder("emptyAllowed", "Bool Template", "../templating/index.md#bool", "Context * Authorization Request", "../context/authorization-request.md", default=False, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use empty password.

!!! warning
    This is explicitly not recommend.

## Context

This authorization will produce a context of type [Authorization Local](../context/authorization.md#local).

## Examples

## Compatibility

| Feature | [`linux`/`generic`](../../setup/distribution.md#linux-generic) | [`linux`/`extended`](../../setup/distribution.md#linux-extended) | [`windows`/`generic`](../../setup/distribution.md#windows-generic) |
| - | - | - | - |
| [PAM](#property-pamService) | <<compatibility(False)>> | <<compatibility(True)>> | <<compatibility(False)>> |
| [yescrypt](#password-yescrypt) | <<compatibility(False)>> | <<compatibility(True)>> | <<compatibility(False)>> |
| anything else | <<compatibility(True)>> | <<compatibility(True)>> | <<compatibility(False)>> |
