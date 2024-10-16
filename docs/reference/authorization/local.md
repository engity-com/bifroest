---
toc_depth: 4
description: How to authorize an user request via the local user database of the host on which Bifröst is running on.
---
# Local authorization

Authorizes a user request via the local user database of the host on which Bifröst is running.

!!! Note
    This authorization requires Bifröst to run with root permissions.

## Properties

<<property("type", "Authorization Type", default="local", required=True)>>
Has to be set to `local` to enable the local authorization.

<<property_with_holder("authorizedKeys", "Array", None, "Authorized Keys", "../data-type.md#authorized-keys", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

The backend type is [Strings Template](../templating/index.md#strings)<[Core](../context/core.md)>.

<<property("password", "Password", "#password")>>
Contains files of with format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be directly used during the authorization process instead of `/etc/passwd` and `/etc/shadow`.

##### Default settings

| <<dist("linux","extended")>> | <<else_ref()>> |
| - | - |
| `sshd` | _empty_ |

## Password

The password can either be validated via `/etc/passwd` and `/etc/shadow` (default) or via PAM (if [`pamService`](#property-pamService) is set to a valid value).

### Properties {. #password-properties}

<<property_with_holder("allowed", "Bool Template", "../templating/index.md#bool", "Context Password Authorization Request", "../context/authorization-request.md#password", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via classic password authentication

<<property_with_holder("interactiveAllowed", "Bool Template", "../templating/index.md#bool", "Context Interactive Authorization Request", "../context/authorization-request.md#interactive", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via interactive authentication.

<<property_with_holder("emptyAllowed", "Bool Template", "../templating/index.md#bool", "Context * Authorization Request", "../context/authorization-request.md", default=False, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use empty passwords.

!!! warning
    This is explicitly not recommend.

## Context

This authorization will produce a context of type [Authorization Local](../context/authorization.md#local).

## Examples

## Compatibility

| Feature | <<dist("linux")>> | <<dist("windows")>> |
| - | - | - |
| [PAM](#property-pamService) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"windows")>> | <<compatibility_editions(False,None,"windows")>> |
