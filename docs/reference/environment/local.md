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
Local account name. `name` or `uid` is required. On Windows, use a bare local SAM name, not a domain-qualified name or an email address. On Unix, an empty name means no name requirement if `uid` is provided.

<<property("uid", "UID", "../data-type.md#uid", template_context="../context/authorization-request.md", requirement="account", heading=4)>>
Desired [user identifier](../data-type.md#uid). On Unix this is the numeric UID. On Windows, it selects an existing local account or checks that `name` resolves to the expected SID. Windows assigns SIDs itself: a missing account cannot be created with an explicitly specified `uid`.

<<property("displayName", "string", template_context="../context/authorization-request.md", requirement="account", heading=4)>>
Desired display name: Linux GECOS, macOS Directory Services real name, or Windows SAM full name. On Windows, an omitted value leaves an existing name unchanged.

<<property("group", "Group", "#group", requirement="account", heading=4)>>
**Unix only.** Desired primary group. Windows has no primary `group` property.

<<property("groups", array_ref("Group", "#group"), requirement="account", heading=4)>>
Supplementary group requirements, each with a `name` and/or [`gid`](../data-type.md#gid). Linux and macOS ensure the configured group set. Windows adds direct memberships in local aliases without removing other memberships. Windows accepts local groups by name or SID, but not domain groups or protected BUILTIN aliases.

<<property("shell", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="/bin/sh", requirement="account", heading=4)>>
**Unix only.** Shell stored on the account. Session-only overrides are available through `shellCommand` and `execCommandPrefix` below.

<<property("homeDir", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="<os specific>", requirement="account", heading=4)>>
**Unix only.** Account home directory. The default is `/home/<user.name>` on Linux and `/Users/<user.name>` on macOS. `directory` below changes only the session's working directory.

On macOS, a managed home must be below a top-level directory, for example `/Users/alice`; a top-level path such as `/Users` is rejected. Bifröst also rejects homes that overlap another local account's home through nesting, case aliases or symlinked parents. Taking over or changing ownership of an existing home fails if its tree contains symlinks, multiply linked files or special files.

<<property("skel", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="<os specific>", requirement="account", heading=4)>>
Source for initial files, used only when Bifröst creates an account. Linux and macOS copy it into the new home directory. Windows copies its contents into the newly created Windows profile as that user, inheriting profile permissions; existing files are never replaced. Use an administrator-controlled source without symlinks, junctions or other reparse points. A failed Windows copy can leave partial content; Bifröst attempts to disable the incomplete account for operator repair.

The default depends on the platform:

* Linux: `/etc/skel`.
* macOS: None.
* Windows: None.

### Account Management

<<property("createIfAbsent", "bool", template_context="../context/authorization-request.md", default=False, heading=4)>>
Create a missing account and enroll it in `managedGroup`. Its template has no `.user`. Without it, a missing account is rejected.

<<property("updateIfDifferent", "bool", template_context="../context/local-environment.md", default=False, heading=4)>>
Update or adopt an existing account and enroll it in `managedGroup`. The template sees the account **before** any changes.

* Linux and macOS: ensure the configured account and group requirements. Updating an existing account by `uid` alone is rejected; set `name` explicitly when using `updateIfDifferent`. UID-only lookups without updates remain supported.
* Windows: update `displayName` and add configured group memberships.
* Both management options `false`: use existing accounts without checking other requirements. On Unix, `createIfAbsent: true` still checks existing accounts without modifying them.

On macOS, Bifröst mutates only records in the local `/Local/Default` Directory Services node. Network and domain identities can be resolved for use but are never modified or deleted. Newly created accounts receive no local password from Bifröst; PAM continues to validate credentials that were provisioned externally.

##### Examples

```yaml
## Update only accounts that already belong to the management group.
updateIfDifferent: "{{ .user.managed }}"
```

Set `updateIfDifferent: true` to permit adopting an existing, unmarked account.

<<property("managedGroup", "string", default="bifroest-managed", heading=4)>>
Static local group that sets [`.user.managed`](../context/local-user.md#property-managed). Membership remains visible if the session repository is lost. It does not restrict an explicitly enabled `deleteOnDispose` or `killProcessesOnDispose`.

<<property("manageSystemUsers", "bool", template_context="../context/authorization-request.md", default=False, heading=4)>>
Explicitly permit management and cleanup of Unix UID 0 or protected Windows accounts such as the built-in Administrator. Unix does **not** automatically classify other service UIDs as system users; use the [Local Environment context](../context/local-environment.md) in the cleanup templates to restrict them. `manageSystemUsers` itself has no `.user` and should be enabled only deliberately.

The cleanup switches under [Dispose](#dispose) are top-level properties of `local`, not a nested `dispose` object.

### Session

For both Unix PTYs and Windows ConPTY, closing SSH standard input alone does not generate a terminal EOF. An interactive program may continue waiting for input; use a non-PTY session for commands that need pipe EOF, or close the session explicitly.

For non-PTY commands and SFTP, after the process exits Bifröst waits up to two seconds for outstanding stdout and stderr forwarding. A write blocked beyond that limit yields a task error and failure audit instead of the process's exit code, even if the SSH client later resumes reading. Remaining output can be lost. This bounded drain prevents a permanently stalled client from holding the session open indefinitely; closing or canceling the session remains independent of that client's write.

<<property("loginAllowed", "bool", template_context="../context/authorization-request.md", default=True, heading=4)>>
Whether this authorization may use the environment.

<<property("variables", "Environment Variables", "../data-type.md#environment-variables", template_context="../context/authorization-request.md", heading=4)>>
Variables for commands and shells. Bifröst-generated identity variables take precedence; names are case-insensitive on Windows.

<<property("banner", "string", template_context="../context/authorization-request.md", default="", heading=4)>>
Text displayed on connection.

<<property("shellCommand", array_ref("string"), template_context="../context/authorization-request.md", default="<os specific>", heading=4)>>
Command and arguments for an interactive shell. An explicit command does not change the stored account shell.

The default depends on the platform:

* Linux and macOS: `[<user's shell>]`
* Windows: `[%COMSPEC%]` (in most cases: `COMSPEC=cmd.exe`)

<<property("execCommandPrefix", array_ref("string"), template_context="../context/authorization-request.md", default="<os specific>", heading=4)>>
Command and arguments prepended to a non-interactive SSH command. The requested command is appended as one argument when a prefix is configured.

The default depends on the platform:

* Linux and macOS: `[<user's shell>, -c]`
* Windows: `[%COMSPEC%, /C]` (in most cases: `COMSPEC=cmd.exe`)

<<property("directory", "File Path", "../data-type.md#file-path", template_context="../context/authorization-request.md", default="<user's home>", heading=4)>>
Working directory for sessions. Defaults to the account home on Unix or profile directory on Windows. If configured, it must exist and be a directory; it does not change the account home or the destination of `skel`.

<<property("portForwardingAllowed", "bool", template_context="../context/authorization-request.md", default=True, heading=4)>>
Allow SSH port forwarding, subject to authorized-key policy. Reverse listeners bind on the Bifröst host; an explicit `*` can expose the listener beyond loopback. On Linux, unprivileged users cannot request reverse listeners on ports `1` through `1023`. Windows outbound forwarding uses the Bifröst process identity.

### Dispose {: #dispose}

<<property("deleteOnDispose", "bool", template_context="../context/local-environment.md", default=False, heading=4)>>
If this evaluates to `true`, the account is deleted when its environment is disposed.

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

* Linux and macOS: the stored path must match, must not be the filesystem root or a shared home, and must be owned by the account. macOS also rejects top-level homes and canonical or nested overlap with another local account's home.
* Windows: profile cleanup follows account deletion; a failed cleanup remains pending for retry.

<<property("killProcessesOnDispose", "bool", template_context="../context/local-environment.md", default="{{ .user.managed }}", heading=4)>>

If `true`, terminate the account's processes after the last active Bifröst session for that account has been disposed and its connections have ended, independently of account deletion. A pending kill survives in the session token. The kill is account-wide and can still affect processes started outside Bifröst under the same identity.

* On Unix, if process cleanup is pending and the account disappears or changes identity, processes are not killed using its old [UID](../data-type.md#uid). Bifröst logs a warning and releases the pending session token once no active session remains; operators must inspect any leftover processes and files manually.
* On Windows, an unidentifiable process blocks cleanup.
* Unreadable sessions or a missing session coordinator block a pending kill instead of assuming no other session is active.
* Completed process cleanup is recorded in the session token and is not repeated while deletion is pending.

See the [upgrade notes](../../setup/upgrade.md#local-environments-and-existing-sessions) for existing Linux sessions with older cleanup tokens and Linux `pidfd` requirements.

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

### OIDC with managed Unix users

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

- On Linux and macOS, changing local accounts or impersonating a different user requires appropriate privileges, usually root. macOS account mutation is limited to the local `/Local/Default` Directory Services node.
- On Windows, session processes for local accounts require Bifröst to run as LocalSystem. Only local SAM accounts are supported; S4U does not provide credentials for remote shares or EFS.
- Windows interactive PTYs require Windows 10 1809 or Windows Server 2019 or later. Older versions support non-PTY commands and SFTP.
- In Windows containers, accounts live inside the container. The default Nano Server entrypoint is not a LocalSystem service. The pinned Nano image has an isolated SAM capability test, but `samcli.dll` availability and runtime behavior have not yet been verified on every host.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
