---
toc_depth: 4
description: How to authorize an user request via the local user database of the host on which Bifröst is running on.
---
# Local authorization

Authorizes a user request via the local user database of the host on which Bifröst is running.

!!! note
     This authorization requires Bifröst to run with root permissions.

## Properties

<<property("type", "Authorization Type", default="local", required=True)>>
Has to be set to `local` to enable the local authorization.

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of certificate authorities that may sign user certificates for existing local users. The requested SSH username must be included in the certificate's principals.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist, contain at least one valid public key, and be no larger than 4 MiB because its keys are materialized during startup.

<<property("authorizedKeys", array_ref("File Path", "../data-type.md#file-path", ref("Authorized Keys", "../data-type.md#authorized-keys")), template_context="../context/core.md", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

An entry with the `cert-authority` option treats its key as a user certificate authority for that local user. The optional `principals="..."` option restricts it further. An empty `authorizedKeys` list does not disable certificate authentication through `trustedUserCAs` or `trustedUserCAsFile`.

On Linux and Darwin, every rendered path must be absolute. Bifröst opens each path component without following symbolic links and accepts only components owned by root or the target user and not writable by group or others. The final file must be a regular file owned by root or the target user, have exactly one hard link, and be no larger than 16 MiB. A missing file is treated as an optional absent key source.

<<property("password", "Password", "#password")>>
See [below](#password).

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be directly used during the authorization process instead of `/etc/passwd` and `/etc/shadow`.

PAM password and keyboard-interactive authentication runs both authentication and account-management checks. A verified public key also has to pass PAM account management before it is accepted, and the check is repeated when a stored local authorization is restored. Account-management policy can therefore reject an otherwise valid password or key because, for example, the account is expired or administratively disabled.

On Darwin, the released extended binary includes PAM and fails closed when `pamService` is empty: password authentication, keyboard-interactive authentication, verified public keys, and restored sessions cannot complete the required local account check. The default `sshd` service uses `/etc/pam.d/sshd`; review that service's policy before exposing Bifröst.

##### Default settings

| <<dist("linux","extended")>> | <<dist("darwin","extended")>> | <<else_ref()>> |
| - | - | - |
| `sshd` | `sshd` | _empty_ |

## Password

On Linux, the password can be validated via `/etc/passwd` and `/etc/shadow` when [`pamService`](#property-pamService) is empty, or via PAM when it is set. A PAM-enabled Darwin build requires a non-empty service and has no local password-repository fallback.

### Properties {. #password-properties}

<<property("allowed", "bool", template_context="../context/authorization-request.md#password", template_context_title="Context Password Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via classic password authentication

<<property("interactiveAllowed", "bool", template_context="../context/authorization-request.md#interactive", template_context_title="Context Interactive Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via interactive authentication.

<<property("emptyAllowed", "bool", template_context="../context/authorization-request.md", template_context_title="Context * Authorization Request", default=False, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use empty passwords.

!!! danger
     This is explicitly not recommend.

## Context

This authorization will produce a context of type [Authorization Local](../context/authorization.md#local).

## Examples

```yaml
type: local
trustedUserCAsFile: /etc/engity/bifroest/trusted-user-cas
authorizedKeys:
  - "{{.user.homeDir}}/.ssh/authorized_keys"
```

User certificates must be current, signed by the selected CA, have the requested SSH username as a principal, and contain no critical options. Missing `permit-pty`, `permit-port-forwarding`, or `permit-agent-forwarding` certificate extensions disable the corresponding capability. Authorized-key options can only restrict these capabilities further.

## Compatibility

| Feature | <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - | - |
| [PAM](#property-pamService) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(None,True,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(None,True,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
