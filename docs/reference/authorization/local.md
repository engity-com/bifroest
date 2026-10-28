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

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of certificate authorities that may sign user certificates for existing local users. The requested SSH username must be included in the certificate's principals.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist, contain at least one valid public key, and be no larger than 4 MiB.

<<property("authorizedKeys", array_ref("File Path", "../data-type.md#file-path", ref("Authorized Keys", "../data-type.md#authorized-keys")), template_context="../context/core.md", default=["{{.user.homeDir}}/.ssh/authorized_keys"])>>
Contains files with the format of classic [authorized keys](../data-type.md#authorized-keys), in which Bifröst will look for [SSH Public Keys](../data-type.md#ssh-public-key).

An entry with the `cert-authority` option treats its key as a user certificate authority for that local user. The optional `principals="..."` option restricts it further. An empty `authorizedKeys` list does not disable certificate authentication through `trustedUserCAs` or `trustedUserCAsFile`.

<<property("password", "Password", "#password")>>
See [below](#password).

<<property("pamService", "string", default="<os and edition specific>")>>
If set to a non-empty value, this [PAM](https://wiki.archlinux.org/title/PAM) service will be directly used during the authorization process instead of `/etc/passwd` and `/etc/shadow`.

On macOS, PAM password and keyboard-interactive authentication runs both authentication and account-management checks. The generic edition fails closed when `pamService` is empty and loads the system PAM library dynamically without CGO. The default `sshd` service uses `/etc/pam.d/sshd`; review that service's policy before exposing Bifröst.

PAM-enabled Linux builds also require both `pam_authenticate` and
`pam_acct_mgmt` for primary password/keyboard-interactive login. Account denial,
expiry or a required password change rejects login; account-phase prompts are
not answered with the primary password. Both phases receive the direct peer in
`PAM_RHOST`. No automatic password change, credential setup or PAM session is run.

PAM is unavailable on Windows; a non-empty `pamService` is rejected there.

##### Default settings

| <<dist("linux","extended")>> | <<dist("darwin")>> | <<else_ref()>> |
| - | - | - |
| `sshd` | `sshd` | _empty_ |

<<property("pamAccountResumeAllowed", "bool", default=False)>>
Explicitly permit secretless browser RememberMe account checks for the configured
PAM service. This requires a PAM-enabled Linux build, a non-empty `pamService`
and the fresh local passwd/group/shadow checker. Other builds reject `true` rather
than ignoring it. The browser's separate RememberMe opt-in is still required.

!!! warning "Review the PAM account stack before opting in"
    Resumption runs `pam_acct_mgmt`, not `pam_authenticate`. It cannot repeat MFA
    or secret-dependent restrictions found only in the PAM `auth` stack. Enable
    this only when all restrictions required on resumption are enforced by the
    service's `account` stack and the local account policy. Otherwise leave it
    disabled and require a fresh regular login. A generic `pam_permit` account
    stack is not proof of equivalent auth policy.

## Password

* On Linux, passwords are validated via `/etc/passwd` and `/etc/shadow` when [`pamService`](#property-pamService) is empty, or via PAM when it is set.
* On macOS, a non-empty PAM service is required; there is no local password-repository fallback.
* On Windows, password and keyboard-interactive authentication validate the password of an existing **local SAM account**. Windows account restrictions (such as disabled accounts or denied network logon) still apply. Domain and Microsoft Entra accounts are not supported by `local` authorization.

### Properties {. #password-properties}

<<property("allowed", "bool", template_context="../context/authorization-request.md#password", template_context_title="Context Password Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via classic password authentication

<<property("interactiveAllowed", "bool", template_context="../context/authorization-request.md#interactive", template_context_title="Context Interactive Authorization Request", default=True, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use passwords via interactive authentication.

<<property("emptyAllowed", "bool", template_context="../context/authorization-request.md", template_context_title="Context * Authorization Request", default=False, id_prefix="password-", heading=4)>>
If `true`, the user is allowed to use empty passwords.

!!! danger
     This is explicitly not recommend.

## Browser RememberMe

Browser password/keyboard-interactive bindings are supported for Linux's
repository-backed local authorization when `pamService` is empty. Both enrollment
and resumption require a fresh independent browser-key proof and native account
eligibility; a session ID or cached user lookup is not authentication. Current
`password.allowed`, `password.interactiveAllowed` and `password.emptyAllowed`
policies remain authoritative for the recorded primary method.

The native checker rereads the configured passwd/group/shadow files before and
after policy validation, pins the stored account name and UID, and rejects locks,
expiry/required password changes, ambiguous or malformed account records and
unavailable/changed files. The group database must be fully decodable; malformed
membership records are not treated as absent groups. Reads are read-only, nonblocking for file locks and
special-file opens, limited to 16 MiB and 100000 records per file. Failure grants
no access and does not repair account or session state. Historical environment
variables, primary passwords and authorization snapshots are not reused.

With [`pamAccountResumeAllowed`](#property-pamAccountResumeAllowed), PAM-backed
Linux password/interactive bindings additionally open a new account-only PAM
transaction, with the current direct peer in `PAM_RHOST`. The canonical `PAM_USER`
must remain the pinned account name and UID. The local account is checked before
and after PAM, and both native policy and PAM are rechecked after request/target
validation. Changed identity, groups or environment fail closed. All account
prompts are rejected, messages are bounded, and only the new transaction's
environment is used. The original password and prior PAM environment are never
available to this transaction. Failure to end PAM or cancellation grants no access.
PAM calls are synchronous: a blocking native module cannot be forcibly canceled
and is never abandoned in a detached worker.

Without that explicit server opt-in PAM-backed resumption remains unavailable.
Darwin PAM and Windows SAM password resumption remain unavailable.
Key/certificate bindings retain
their existing current-key checks. RememberMe is opt-in and uses the common
[HTTP binding lifecycle](../connection/http.md#rememberme), including independent
browser keys and logout without session/workload disposal.

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

User certificates must be current, signed by the selected CA, have the requested SSH username as a principal, and contain no critical options. Missing `permit-pty`, `permit-port-forwarding`, or `permit-agent-forwarding` certificate extensions disable the corresponding capability. Authorized-key options can only restrict these capabilities further.

## Compatibility

| Feature | <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - | - |
| [PAM](#property-pamService) | <<compatibility_editions(False,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(False,None,"windows")>> |
| <<else_ref()>> | <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
