---
toc_depth: 4
description: How to authorize an user request via the local user database of the host on which Bifröst is running on.
---
# Local authorization

Authorizes a user request via the local user database of the host on which Bifröst is running.

!!! note
     On Linux, this authorization requires Bifröst to run with root permissions.<br>
     On Windows, the default [`authorizedKeys`](#property-authorizedKeys) path uses `.user.homeDir`, which requires LocalSystem to resolve the user's profile via S4U. For a custom path without `.user.homeDir`, Bifröst only needs permission to read the file. The Windows local environment also requires LocalSystem to start processes as the local account.

## Properties

<<property("type", "Authorization Type", default="local", required=True)>>
Has to be set to `local` to enable the local authorization.

<<property("rememberMe", "RememberMe", "../data-type.md#rememberme", default="forbidden")>>
Controls saved browser and SSH access. Resumption requires key-possession proof, the same account name and UID/SID, and current account and access checks. Missing required checks deny resumption; no password is saved or replayed. Registered SSH keys need not appear in `authorized_keys`. Windows requires LocalSystem and local SAM accounts; see [Compatibility](#compatibility).

!!! warning
    Saved access skips repeated password/MFA authentication. With PAM, the `account` stack must enforce the required restrictions; `auth` is not repeated.

<<property("remoteName", "string", template_context="../context/authorization-request.md", default="{{.remote.user}}")>>
Account name used for native lookup and credential checks. The original requesting name remains unchanged in flow requirements and audit records. Mapping creates no account and grants no OS rights; see the [example](#login-name-with-an-ssh-suffix).

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of certificate authorities that may sign user certificates for existing local users. The resolved `remoteName` must be included in the certificate's principals; by default this is the requesting name.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist, contain at least one valid public key, and be no larger than 4 MiB.

<<property("authorizedKeys", array_ref("File Path", "../data-type.md#file-path", ref("Authorized Keys", "../data-type.md#authorized-keys")), template_context="../context/authorization-request.md", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

Each file must be a regular file no larger than 4 MiB. On Unix, the file and its directories must be owned by root, the Bifröst service account, or the selected user, and must not be writable by other users (root-owned sticky directories are allowed). Symbolic links in the path are rejected.

The request's `.connection` and the selected native [`.user`](../context/local-user.md) are available; `.remote.user` remains the original requesting name.

An entry with the `cert-authority` option treats its key as a user certificate authority for that local user. The optional `principals="..."` option restricts it further. An empty `authorizedKeys` list does not disable certificate authentication through `trustedUserCAs` or `trustedUserCAsFile`.

User certificates must be current, signed by the selected CA, have the resolved `remoteName` as a principal, and contain no critical options. Missing `permit-pty`, `permit-port-forwarding`, or `permit-agent-forwarding` certificate extensions disable the corresponding capability. Authorized-key options can only restrict these capabilities further.

<<property("password", "Password", "#password")>>
See [below](#password).

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be directly used during the authorization process instead of `/etc/passwd` and `/etc/shadow`.

Fresh PAM logins must pass authentication and account checks. Account denial, a required password change or an account-phase prompt rejects login; Bifröst does not change passwords or open a PAM session. The direct peer is supplied as `PAM_RHOST`.

On macOS this property must be non-empty. For supported platforms and editions, see [Compatibility](#compatibility).

##### Default settings

| <<dist("linux","extended")>> | <<dist("darwin","generic")>> | <<else_ref()>> |
| - | - | - |
| `sshd` | `sshd` | _empty_ |

## Password

* On Linux, passwords are validated via `/etc/passwd` and `/etc/shadow` when [`pamService`](#property-pamService) is empty, or via PAM when it is set.
  Without PAM, an expired password or one requiring a change cannot be used to log in; Bifröst does not change passwords.
* On macOS, a non-empty PAM service is required; there is no local password-repository fallback.
* On Windows, password and keyboard-interactive authentication validate the password of an existing **local SAM account**. Windows account restrictions (such as disabled accounts or denied network logon) still apply. Domain and Microsoft Entra accounts are not supported by `local` authorization.

### Properties {: #password-properties}

<<property("allowed", "bool", template_context="../context/authorization-request.md#password", template_context_title="Context Password Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via classic password authentication.

<<property("interactiveAllowed", "bool", template_context="../context/authorization-request.md#interactive", template_context_title="Context Interactive Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via interactive authentication.

<<property("emptyAllowed", "bool", template_context="../context/authorization-request.md", template_context_title="Context * Authorization Request", default=False, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use empty passwords.

!!! danger
     Allowing empty passwords is not recommended.

## Context

This authorization will produce a context of type [Authorization Local](../context/authorization.md#local).

## Examples

### Using OpenSSH Certificates

```yaml
type: local
rememberMe: allowedAndEnabledByDefault
trustedUserCAsFile: /etc/engity/bifroest/trusted-user-cas
authorizedKeys:
  - "{{.user.homeDir}}/.ssh/authorized_keys"
```

### Using Local accounts

```yaml
flows:
  - name: local
    authorization:
      type: local
      rememberMe: allowedAndEnabledByDefault
    environment:
      type: local
      name: '{{ .authorization.user.name }}'
      uid: '{{ .authorization.user.uid }}'
```

### RememberMe with PAM

Use an existing PAM service whose account stack enforces the required access restrictions:

```yaml
type: local
rememberMe: allowedAndEnabledByDefault
pamService: bifroest
```

### Login name with an SSH suffix

Authenticate SSH login `foo@bar` as the existing account `foo`, while keeping HTTP login names unchanged:

```yaml
type: local
rememberMe: allowedAndEnabledByDefault
remoteName: >
  {{- if eq .connection.transport "ssh" -}}
    {{- regexReplaceAll "@[^@]+$" .remote.user "" -}}
  {{- else -}}
    {{- .remote.user -}}
  {{- end -}}
```

[Flow requirements](../flow.md#requirement) still match the original name: use `requirement.ssh.includedRequestingName: '@bar$'` for this suffix and, for example, `requirement.http.includedSlug: '^docker$'` for the browser link. Connect with `ssh -l 'foo@bar' bifroest.example.org`, or open `/#docker` and enter `foo`.

## Compatibility

| Feature | <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - | - |
| [PAM](#property-pamService) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| [Password/interactive RememberMe without PAM](#property-rememberMe) | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
| [RememberMe with PAM](#property-rememberMe) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
