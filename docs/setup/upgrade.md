---
description: Migration notes for upgrading Bifröst from the previous minor release.
---

# Upgrade notes

## From the previous minor series to <<release_name()>>

These notes apply to an upgrade from any patch release in the previous minor series to <<release_name()>>. Patch releases within the same minor series share these upgrade notes.

<p id="upgrade-predecessor" data-release="<<release_name()>>" hidden></p>

### Filesystem session storage

The filesystem session repository now uses an exclusive operating-system lock. Before upgrading, stop every Bifröst process using the same session storage. Only one process can open a storage at a time after the upgrade.

The lock file is created next to the configured storage as `.<storage-name>.bifroest.lock`. Ensure the parent directory is writable by the Bifröst process. Storage symlinks are canonicalized so aliases share the same lock; dangling storage symlinks are rejected at startup. Existing session files remain compatible and require no conversion.

### Session maximum timeout

`session.maxTimeout` is now enforced from session creation, rather than from last access. Existing sessions that have already exceeded their configured maximum lifetime may expire earlier, or immediately, after the upgrade.

### Flow validation

Flow names must be unique. The special path components `.` and `..` are no longer accepted as flow names. Update configurations with duplicate or invalid names before starting the new release.

### Environment variable precedence

Environment variables are applied in the following order, with later sources overriding earlier ones:

1. Variables accepted from the SSH client.
2. Variables specified by an `authorized_keys` policy.
3. Variables supplied by the authorization, including PAM.
4. Variables configured for the environment.

Authorization variables therefore take precedence over colliding SSH-client or `authorized_keys` variables. On Windows, variable names are compared case-insensitively and ambiguous names within one layer are rejected.

### New SSH features

SSH environments, SSH user certificates, Bifröst authorization and their key-bootstrap commands are new in this minor release. They do not require migration of an existing installation.

### Docker and Kubernetes sessions

Existing containers and Pods without matching declared execution-lifecycle and IMP protocol revisions cannot be reused. A missing IMP protocol revision is treated as revision 1. A normal login refuses reuse without deleting the resource, even when automatic cleanup is allowed. Housekeeping proactively disposes sessions with *known* incompatible metadata as a whole, including active, not-yet-expired sessions and their environments; explicit environment disposal also removes the resource. Invalid revision metadata or inspection failures cannot prove incompatibility and require operator inspection instead. Back up container-local data, anonymous volumes and Pod-local ephemeral data before upgrading. See the [Docker](../reference/environment/docker.md#execution-lifecycle-and-upgrades) and [Kubernetes](../reference/environment/kubernetes.md#execution-lifecycle-and-upgrades) lifecycle notes for the distinct storage and cleanup behavior.

### Local environments and existing sessions

Persisted Linux `local` environment tokens written before the cleanup-token format with a `version` field are **not migrated**. Even if an old token contains `user.deleteOnDispose`, its previous account, home-directory and process cleanup decisions are not run by the new version. When such a session is disposed, its token is removed; the account, home directory and processes may remain. This is intentional to avoid deleting an account using an old, insufficiently verified identity snapshot.

Before upgrading, identify accounts whose cleanup depended on those existing sessions. If cleanup is needed, complete it before the upgrade or reconcile the remaining accounts manually after verifying their current identity, home ownership and active sessions. Do not assume that changing the new configuration will clean up sessions whose tokens were already written.

For **new** sessions, configure the top-level [`deleteOnDispose`](../reference/environment/local.md#property-deleteOnDispose) and [`killProcessesOnDispose`](../reference/environment/local.md#property-killProcessesOnDispose) settings for the desired policy. The former defaults to `false`; the latter defaults to `{{ .user.managed }}`. Legacy nested `dispose.*` settings must be replaced with the current top-level settings.

On Linux, process cleanup uses `pidfd_open` and `pidfd_send_signal`. It requires a kernel with `pidfd_open` support (Linux 5.3 or newer) and a security profile that permits both syscalls. If either call is unavailable or blocked, process cleanup fails closed and an account deletion waiting on it is not performed. Disabling `killProcessesOnDispose` for new sessions avoids this prerequisite, but may leave processes running when their account is removed.

### Windows local environments

Every Windows flow using `environment.type: local` must now identify an existing **local** Windows account with `environment.name` or `environment.uid` (its SID). Previously, a missing account selection could run shell and SFTP processes under the Bifröst service identity (often LocalSystem); that configuration is now rejected. For example, if a `simple` authorization entry name matches a local account:

```yaml
environment:
  type: local
  name: "{{.authorization.entry.name}}"
```

For OIDC, explicitly map a verified claim to the local account name; an email address is not automatically a Windows account name. Run Bifröst as LocalSystem for passwordless S4U process startup. With the account-management defaults used in this example, Bifröst does not create, modify or delete local users. Existing saved Windows local sessions without a bound account SID cannot be reused and require reauthorization.

PTY requires ConPTY (Windows 10 1809 / Windows Server 2019 or newer). Older supported Windows versions still accept non-PTY commands and SFTP but reject PTY requests. S4U does not provide the account's network credentials or EFS access; SSH TCP forwarding continues under the Bifröst service identity.
