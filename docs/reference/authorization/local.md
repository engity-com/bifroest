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

<<property("remoteName", "string", template_context="../context/authorization-request.md", default="{{.remote.user}}")>>
Account name used for native lookup and credential checks. The original requesting name remains unchanged in flow requirements and audit records. Mapping creates no account and grants no OS rights; see the [example](#login-name-with-an-ssh-suffix).

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of certificate authorities that may sign user certificates for existing local users. The resolved `remoteName` must be included in the certificate's principals; by default this is the requesting name.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist, contain at least one valid public key, and be no larger than 4 MiB.

<<property("authorizedKeys", array_ref("File Path", "../data-type.md#file-path", ref("Authorized Keys", "../data-type.md#authorized-keys")), template_context="../context/authorization-request.md", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

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

<<property("pamAccountResumeAllowed", "bool", default=False)>>
Allow browser RememberMe through the PAM `account` stack without repeating `auth` or MFA. Requires a non-empty [`pamService`](#property-pamService); support is listed under [Compatibility](#compatibility).

!!! warning
    Enable only if the PAM account stack enforces all restrictions required for resumption. Checks present only in the auth stack are not repeated.

## Password

* On Linux, passwords are validated via `/etc/passwd` and `/etc/shadow` when [`pamService`](#property-pamService) is empty, or via PAM when it is set.
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

## Browser RememberMe

Requires browser-key proof, the same native account name and UID/SID, and current account, credential and target policy. Unavailable policy checks deny resumption; no password is saved or replayed. Windows requires a LocalSystem service and local SAM accounts. See [Compatibility](#compatibility) for platform support and [HTTP RememberMe](../connection/http/index.md#rememberme) for browser opt-in and logout.

## Context

This authorization will produce a context of type [Authorization Local](../context/authorization.md#local).

## Examples

### Using OpenSSH Certificates

```yaml
type: local
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
    environment:
      type: local
      name: '{{ .authorization.user.name }}'
      uid: '{{ .authorization.user.uid }}'
```

### Allow PAM account checks for browser RememberMe

Use an existing PAM service whose account stack meets the [resumption requirements](#property-pamAccountResumeAllowed):

```yaml
type: local
pamService: bifroest
pamAccountResumeAllowed: true
```

### Login name with an SSH suffix

Authenticate SSH login `foo@bar` as the existing account `foo`, while keeping HTTP login names unchanged:

```yaml
type: local
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
| [Password/interactive RememberMe without PAM](#browser-rememberme) | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
| [PAM RememberMe](#property-pamAccountResumeAllowed) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
