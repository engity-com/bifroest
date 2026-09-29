---
description: Run SSH sessions as local users on the Bifröst host.
toc_depth: 4
---

# Local environment

Run SSH sessions as local users on the Bifröst host. Use existing accounts or optionally create, update and remove them.

## Configuration

<<property("type", "Environment Type", default="local", required=True, heading=3)>>
Must be `local`.

### Account {: #account}

<<property("name", "string", template_context="../context/authorization-request.md", requirement="account", heading=4)>>
Local account name. On Windows, `name` or `uid` is required; use a bare local SAM name, not a domain-qualified name or an email address. On Linux, an empty name means no name requirement if `uid` is provided.

<<property("uid", "UID", "../data-type.md#uid", template_context="../context/authorization-request.md", requirement="account", heading=4)>>
Desired [user identifier](../data-type.md#uid). On Windows, it selects an existing local account or checks that `name` resolves to the expected SID. Windows assigns SIDs itself: a missing account cannot be created with an explicitly specified `uid`.

<<property("displayName", "string", template_context="../context/authorization-request.md", requirement="account", heading=4)>>
Desired display name: Linux GECOS or Windows SAM full name. On Windows, an omitted value leaves an existing name unchanged.

<<property("group", "Group", "#group", requirement="account", heading=4)>>
**Linux only.** Desired primary group. Windows has no primary `group` property.

<<property("groups", array_ref("Group", "#group"), requirement="account", heading=4)>>
Supplementary group requirements, each with a `name` and/or [`gid`](../data-type.md#gid). Linux ensures the configured group set. Windows adds direct memberships in local aliases without removing other memberships. Windows accepts local groups by name or SID, but not domain groups or protected BUILTIN aliases.

<<property("shell", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="/bin/sh", requirement="account", heading=4)>>
**Linux only.** Shell stored on the account. Session-only overrides are available through `shellCommand` and `execCommandPrefix` below.

<<property("homeDir", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="/home/<user.name>", requirement="account", heading=4)>>
**Linux only.** Account home directory. `directory` below changes only the session's working directory.

<<property("skel", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="<os specific>", requirement="account", heading=4)>>
Source for initial files, used only when Bifröst creates an account. Linux copies it into the new home directory. Windows copies its contents into the newly created Windows profile as that user, inheriting profile permissions; existing files are never replaced. Use an administrator-controlled source without junctions or other reparse points. A failed Windows copy can leave partial content; Bifröst attempts to disable the incomplete account for operator repair.

The default depends on the platform:

* Linux: `/etc/skel`.
* Windows: None.

### Account Management

<<property("createIfAbsent", "bool", template_context="../context/authorization-request.md", default=False, heading=4)>>
Create a missing account and enroll it in `managedGroup`. Its template has no `.user`. Without it, a missing account is rejected.

<<property("updateIfDifferent", "bool", template_context="../context/local-environment.md", default=False, heading=4)>>
Update or adopt an existing account and enroll it in `managedGroup`. The template sees the account **before** any changes.

* Linux: ensure the configured account and group requirements. Updating an existing account by `uid` alone is rejected; set `name` explicitly when using `updateIfDifferent`. UID-only lookups without updates remain supported.
* Windows: update `displayName` and add configured group memberships.
* Both management options `false`: use existing accounts without checking other requirements. On Linux, `createIfAbsent: true` still checks existing accounts without modifying them.

##### Examples

```yaml
## Update only accounts that already belong to the management group.
updateIfDifferent: "{{ .user.managed }}"
```

Set `updateIfDifferent: true` to permit adopting an existing, unmarked account.

<<property("managedGroup", "string", default="bifroest-managed", heading=4)>>
Static local group that sets [`.user.managed`](../context/local-user.md#property-managed). Membership remains visible if the session repository is lost. It does not restrict an explicitly enabled `deleteOnDispose` or `killProcessesOnDispose`.

<<property("manageSystemUsers", "bool", template_context="../context/authorization-request.md", default=False, heading=4)>>
Explicitly permit cleanup of Linux UID 0 or protected Windows accounts such as the built-in Administrator. Linux does **not** automatically classify other service UIDs as system users; use the [Local Environment context](../context/local-environment.md) in the cleanup templates to restrict them. `manageSystemUsers` itself has no `.user` and should be enabled only deliberately.

The cleanup switches under [Dispose](#dispose) are top-level properties of `local`, not a nested `dispose` object.

### Session

<<property("loginAllowed", "bool", template_context="../context/authorization-request.md", default=True, heading=4)>>
Whether this authorization may use the environment.

<<property("variables", "Environment Variables", "../data-type.md#environment-variables", template_context="../context/authorization-request.md", heading=4)>>
Variables for commands and shells. Bifröst-generated identity variables take precedence; names are case-insensitive on Windows.

<<property("banner", "string", template_context="../context/authorization-request.md", default="", heading=4)>>
Text displayed on connection.

<<property("shellCommand", array_ref("string"), template_context="../context/authorization-request.md", default="<os specific>", heading=4)>>
Command and arguments for an interactive shell. An explicit command does not change the stored account shell.

The default depends on the platform:

* Linux: `[<user's shell>]`
* Windows: `[%COMSPEC%]` (in most cases: `COMSPEC=cmd.exe`)

<<property("execCommandPrefix", array_ref("string"), template_context="../context/authorization-request.md", default="<os specific>", heading=4)>>
Command and arguments prepended to a non-interactive SSH command. The requested command is appended as one argument when a prefix is configured.

The default depends on the platform:

* Linux: `[<user's shell>, -c]`
* Windows: `[%COMSPEC%, /C]` (in most cases: `COMSPEC=cmd.exe`)

<<property("directory", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="<user's home>", heading=4)>>
Working directory for sessions. Defaults to the account home on Linux or profile directory on Windows. If configured, it must exist and be a directory; it does not change the account home or the destination of `skel`.

<<property("portForwardingAllowed", "bool", template_context="../context/authorization-request.md", default=True, heading=4)>>
Allow SSH port forwarding, subject to authorized-key policy. Reverse listeners bind on the Bifröst host; an explicit `*` can expose the listener beyond loopback. On Linux, unprivileged users cannot request reverse listeners on ports `1` through `1023`. Windows outbound forwarding uses the Bifröst process identity.

### Dispose {: #dispose}

<<property("deleteOnDispose", "bool", template_context="../context/local-environment.md", default=False, heading=4)>>
If evaluates to `true`, the is deleted account when its environment is disposed.

* Protected accounts require [`manageSystemUsers: true`](#property-manageSystemUsers).
* Deletion waits until no other active session in the same repository uses the account.
* Pending deletion survives restarts in the session token. Unreadable sessions or a changed [UID](../data-type.md#uid) block deletion.
* Independent instances with separate repositories cannot see each other's sessions. Losing the repository also loses automatic cleanup.

##### Examples

```yaml
## Automatically deleted by Bifröst managed user/accounts,
## but no other user/account.
deleteOnDispose: "{{ .user.managed }}"
```

<<property("deleteHomeTogetherWithUser", "bool", template_context="../context/local-environment.md", default=True, heading=4)>>

If this property is `true` and [`deleteOnDispose`](#property-deleteOnDispose) actually deletes the account, remove its home/profile too.

* Linux: the stored path must match, must not be the filesystem root or a shared home, and must be owned by the account.
* Windows: profile cleanup follows account deletion; a failed cleanup remains pending for retry.

<<property("killProcessesOnDispose", "bool", template_context="../context/local-environment.md", default="{{ .user.managed }}", heading=4)>>

If `true`, terminate the account's processes on session disposal, independently of account deletion. This can interrupt other active sessions. By default, it applies to accounts in `managedGroup`.

* A removed account's processes can still be targeted by its stored [UID](../data-type.md#uid), unless Linux has reassigned that [UID](../data-type.md#uid).
* On Windows, an unidentifiable process blocks cleanup.
* Completed process cleanup is recorded in the session token and is not repeated while deletion is pending.

##### Examples

###### Automatically kill all Biföst manged account's processes
```yaml
killProcessesOnDispose: "{{ .user.managed }}"
```

###### Automatically kill account's processes
```yaml
killProcessesOnDispose: true
```

## Group {: #group}

<<property("name", "string", template_context="../context/authorization-request.md", id_prefix="group-", heading=3)>>
Name of a Unix group or local Windows alias.

<<property("gid", "GID", "../data-type.md#gid", template_context="../context/authorization-request.md", id_prefix="group-", heading=3)>>
[Group identifier](../data-type.md#gid). On Windows, a specified name and GID must resolve to the same local group; Windows cannot assign an arbitrary SID to a newly created group.


## Examples

### Existing local account

```yaml
type: local
name: "{{.authorization.user.name}}" # Linux local authorization
```

### OIDC with managed Linux users

```yaml
type: local
name: "{{.authorization.idToken.email}}"
displayName: "{{.authorization.idToken.name}}"
groups:
  - name: oidc
createIfAbsent: true
updateIfDifferent: true
deleteOnDispose: true
```

### OIDC with managed Windows users

```yaml
type: local
name: "{{.authorization.idToken.local_user}}"
groups:
  - name: oidc
skel: 'C:\bootstrap-profile'
createIfAbsent: true
updateIfDifferent: "{{.user.managed}}" # Do not adopt an unmarked account.
deleteOnDispose: "{{.user.managed}}"
```

## Requirements

- On Linux, changing local accounts or impersonating a different user requires appropriate privileges, usually root.
- On Windows, session processes for local accounts require Bifröst to run as LocalSystem. Only local SAM accounts are supported; S4U does not provide credentials for remote shares or EFS.
- Windows interactive PTYs require Windows 10 1809 or Windows Server 2019 or later. Older versions support non-PTY commands and SFTP.
- In Windows containers, accounts live inside the container. The default Nano Server entrypoint is not a LocalSystem service. The pinned Nano image has an isolated SAM capability test, but `samcli.dll` availability and runtime behavior have not yet been verified on every host.

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
