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
Resolve the account name before native lookup, password/PAM authentication or
authorized-key evaluation. The original requesting name is not changed. Native
account, password, PAM and Windows policies still apply; mapping grants no OS
rights and creates no account. See [login-name mapping](login-name-mapping.md).

For example, SSH `foo@bar` selects native account `foo`, while HTTP keeps the
entered name unchanged and can select the flow through its slug:

```yaml
remoteName: '{{if eq .connection.transport "ssh"}}{{regexReplaceAll "@[^@]+$" .remote.user ""}}{{else}}{{.remote.user}}{{end}}'
```

[Flow requirements](../flow.md#requirement) still check the original login name.
`requirement.includedRequestingName: '^docker$'` matches only `docker`, not
`foo@bar`. Use `requirement.ssh.includedRequestingName: '@bar$'` for SSH and
`requirement.http.includedSlug: '^docker$'` for HTTP; see the
[combined flow example](login-name-mapping.md#ssh-suffix-and-http-slug).

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of certificate authorities that may sign user certificates for existing local users. The resolved `remoteName` must be included in the certificate's principals; by default this is the requesting name.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist, contain at least one valid public key, and be no larger than 4 MiB.

<<property("authorizedKeys", array_ref("File Path", "../data-type.md#file-path", ref("Authorized Keys", "../data-type.md#authorized-keys")), template_context="../context/authorization-request.md", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

The request's `.connection` is available together with the selected native
[`.user`](../context/local-user.md) candidate. `.remote.user` still contains the
original requesting name, not the mapped account name.

An entry with the `cert-authority` option treats its key as a user certificate authority for that local user. The optional `principals="..."` option restricts it further. An empty `authorizedKeys` list does not disable certificate authentication through `trustedUserCAs` or `trustedUserCAsFile`.

User certificates must be current, signed by the selected CA, have the resolved `remoteName` as a principal, and contain no critical options. Missing `permit-pty`, `permit-port-forwarding`, or `permit-agent-forwarding` certificate extensions disable the corresponding capability. Authorized-key options can only restrict these capabilities further.

<<property("password", "Password", "#password")>>
See [below](#password).

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be directly used during the authorization process instead of `/etc/passwd` and `/etc/shadow`.

On Linux and macOS, PAM password and keyboard-interactive login must pass both
authentication and account-management checks. Account denial, expiry or a required
password change rejects login. Account-phase prompts are rejected.
No automatic password change or PAM session is run.
The direct peer is supplied as `PAM_RHOST`.

On macOS, `pamService` must be non-empty; there is no local password-repository
fallback. The default `sshd` service uses `/etc/pam.d/sshd`. Review the selected
service's policy before exposing Bifröst.

PAM is unavailable on Windows; a non-empty `pamService` is rejected there.

##### Default settings

| <<dist("linux","extended")>> | <<dist("darwin")>> | <<else_ref()>> |
| - | - | - |
| `sshd` | `sshd` | _empty_ |

<<property("pamAccountResumeAllowed", "bool", default=False)>>
Permit browser RememberMe resumption through PAM account checks without a password.
Requires a PAM-enabled Linux build, a non-empty `pamService` and current native
account checks. Unsupported builds reject `true`. The user's separate browser
RememberMe opt-in is still required.

!!! warning "Review the PAM account stack before opting in"
    Resumption runs `pam_acct_mgmt`, not `pam_authenticate`. It cannot repeat MFA
    or secret-dependent restrictions found only in the PAM `auth` stack. Enable
    this only when all restrictions required on resumption are enforced by the
    service's `account` stack and the local account policy. Otherwise leave it
    disabled and require a fresh regular login. A `pam_permit` account stack
    alone does not provide equivalent authentication policy.

A blocking native PAM module cannot be forcibly interrupted by Bifröst.

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

Enrollment and resumption require an independent browser-key proof and current
account eligibility. The original account name and UID/SID must still match.
For password/keyboard-interactive bindings, current method, empty-password, group
and target policies are rechecked. Disabled, locked or expired accounts and required
password changes prevent password resumption.

* **Linux without PAM:** supported with the local passwd/group/shadow repository
  and `pamService: ""`.
* **Linux with PAM:** also requires [`pamAccountResumeAllowed`](#property-pamAccountResumeAllowed).
  Each resumption checks the current PAM account policy; it does not repeat
  password authentication or reuse an earlier PAM environment.
* **Windows:** supported for local SAM accounts with an unimpersonated LocalSystem
  service and the required native APIs. Current native account and network-logon
  restrictions apply. A native blank-password restriction overrides `password.emptyAllowed`.
  Bifröst does not grant logon rights, enable TCB privileges or relax account policy.
* **macOS:** password/keyboard-interactive resumption is not supported. Use a fresh
  PAM login instead.

Unavailable or inconclusive native checks deny resumption. No saved password or
previous rights are replayed. Key/certificate bindings must still pass current
key and certificate policy. See [HTTP RememberMe](../connection/http/index.md#rememberme)
for opt-in and logout, and [security limits](../connection/http/security.md) for
browser-key protection. Logout does not dispose of the session or its workload.

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

Use only after reviewing a PAM service whose account stack enforces all required
resumption restrictions; this does not repeat auth-stack MFA.

```yaml
type: local
pamService: bifroest
pamAccountResumeAllowed: true
```

The `bifroest` PAM service must already be configured on the host. Leave the flag
`false` if account-only checks are insufficient.

## Compatibility

| Feature | <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - | - |
| [PAM](#property-pamService) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| [Browser password/interactive RememberMe without PAM](#browser-rememberme) | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
| [PAM browser RememberMe (explicit opt-in)](#property-pamAccountResumeAllowed) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(False,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
