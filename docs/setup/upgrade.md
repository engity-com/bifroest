---
description: Actions and behavior to consider when upgrading Bifröst from v0.7.x.
---

# Upgrade from v0.7.x to <<release_name()>> {: #upgrade-notes .upgrade-notes-headline data-release="<<release_name()>>" }

These notes apply to an upgrade from any v0.7.x release to <<release_name()>>. They document upgrade actions and behavior changes, not release notes. Patch releases within the new series share these upgrade notes.

<p id="upgrade-predecessor" data-release="<<release_name()>>" hidden></p>

## Session storage

### `session.storage` (filesystem)

The filesystem session repository now holds an exclusive operating-system lock. Before starting the upgraded Bifröst, stop every process using the same storage: only one process can open it at a time.

The lock file, `.<storage-name>.bifroest.lock`, is created next to the **resolved** storage directory. Check that its parent directory and any existing lock file are writable. Storage symlinks resolve to the same lock; a symlink pointing to a missing directory prevents startup. Existing session metadata needs no conversion.

### `session.maxTimeout`

If set, the maximum lifetime now counts from session creation rather than last access. Check active sessions and this setting before upgrading: some sessions may expire earlier or immediately.

Sessions saved by the previous minor series have no creation timestamp. For them, Bifröst uses the modification time of the session metadata file, which may differ from the actual creation time.

## Flows

### `flows[].name`

Flow names must be unique, may not be `.` or `..`, and may not exceed 255 bytes. Correct existing names that violate these rules before starting the upgraded version, or configuration validation will fail.

## Authorizations

### OIDC Device Auth

OIDC now defaults to `forceDisposeSessionOn: lostAccess` and `refreshToken.mode: proactive`. Before upgrading, ensure your identity provider issues refresh tokens for the configured client and scopes (often requiring `offline_access`). Otherwise, new OIDC logins will be rejected. Bifröst does not add provider-specific scopes automatically.

Previously created sessions without a refresh token or recorded identity will be disposed when the upgraded service starts. Users of those sessions must authenticate again; running work may be interrupted.

To temporarily retain the previous behavior while configuring your identity provider, explicitly set **both** properties in the OIDC authorization:

```yaml
forceDisposeSessionOn: never
refreshToken:
  mode: never
```

See the [OIDC authorization reference](../reference/authorization/oidc.md#device-auth) for the full configuration and examples.

## Environments

### All environment types

#### Execution environment variables

User-supplied variables now use the following precedence, with later sources overriding earlier ones:

1. Variables accepted from the SSH client.
2. Variables specified by an `authorized_keys` policy.
3. Variables supplied by the authorization, including PAM.
4. Variables configured for the environment.

Previously, SSH-client and `authorized_keys` variables could override authorization variables. Check policies that rely on colliding names. For Windows targets, names are case-insensitive: conflicting spellings in a single authorization or configured-environment map are rejected; repeated SSH-client names overwrite each other. Bifröst may set its own execution variables afterward.

### Docker and Kubernetes

#### Existing IMP sessions

Containers and Pods from the previous minor series lack the required execution-lifecycle and IMP protocol revision metadata. A new login cannot reuse them and does not remove them. Housekeeping also checks active sessions: when it can establish incompatibility, it attempts to dispose the **entire session**, including the container or Pod and authorization. Running work may be interrupted.

You do not generally need to remove old resources yourself. **Before starting the upgraded Bifröst**, back up any needed container-local data, anonymous Docker volumes, and Pod-local ephemeral data. Persistent volumes have their own lifecycle. Invalid metadata, ambiguous ownership, and inspection or disposal failures require operator review. Changing resource metadata does not upgrade the IMP binary. See the [Docker](../reference/environment/docker.md#execution-lifecycle-and-upgrades) and [Kubernetes](../reference/environment/kubernetes.md#execution-lifecycle-and-upgrades) details.

#### Linux execution-scoped signals

If you use execution-scoped signals in Linux containers or Pods, check for Linux 5.3 or newer and a seccomp profile allowing `pidfd_open` and `pidfd_send_signal`. Otherwise signal requests fail.

### Linux (`local`)

#### Existing session cleanup tokens

Persisted `local` tokens from the previous minor series have no cleanup-token `version` field. Their account, home-directory, and process cleanup decisions are **not migrated**. Successful disposal can remove a token while leaving the account, home directory, and processes behind; the old identity snapshot is insufficient for safe deletion.

Before upgrading, identify accounts whose cleanup relied on existing sessions. Complete any needed cleanup before the upgrade, or afterward verify account identity, home ownership, and active sessions before reconciling them manually. Changing the new configuration cannot restore cleanup decisions in old tokens.

#### `environment.dispose.*`

The previous minor series accepted these Linux `local` settings, which the upgraded version rejects if explicitly set:

- `dispose.deleteManagedUser`: review [`deleteOnDispose`](../reference/environment/local.md#property-deleteOnDispose).
- `dispose.deleteManagedUserHomeDir`: review [`deleteHomeTogetherWithUser`](../reference/environment/local.md#property-deleteHomeTogetherWithUser).
- `dispose.killManagedUserProcesses`: review [`killProcessesOnDispose`](../reference/environment/local.md#property-killProcessesOnDispose).

Remove the old settings before starting the upgraded version. Choose the top-level policies deliberately for **new** sessions: these are not one-to-one renames, since defaults and managed-user identification have changed. Account deletion now defaults to `false`.

#### `environment.killProcessesOnDispose`

Process cleanup now defaults to `{{ .user.managed }}`. For newly managed accounts it can run even without account deletion and may terminate other processes owned by that account. Review this policy before upgrading; set `killProcessesOnDispose: false` if that is not intended.

When process cleanup applies, it requires `pidfd_open` and `pidfd_send_signal` (Linux 5.3 or newer, with both syscalls allowed by the security profile). If unavailable, cleanup fails closed and a dependent account deletion does not proceed. Disabling process cleanup avoids this prerequisite but may leave processes running.

### Windows (`local`)

#### `environment.name` or `environment.uid`

Every Windows `local` flow must now select a **local SAM account** by name or SID. Without an account selection, shell and SFTP previously ran as the Bifröst service identity (often LocalSystem); the upgraded version rejects that configuration. By default the account must exist; creating one requires an explicit `createIfAbsent` policy.

For example, if a `simple` authorization entry names an existing local account:

```yaml
environment:
  type: local
  name: "{{.authorization.entry.name}}"
```

For OIDC, map a verified claim to the account name; an email address is not automatically a Windows account name. With the account-management defaults in this example, Bifröst does not create, modify, or delete local users.

#### Service identity and existing sessions

Run Bifröst as LocalSystem for S4U session process startup, and check the selected account's permissions. S4U does not provide that account's network credentials or EFS access; check workloads that previously relied on the service identity. Saved Windows `local` sessions without a bound account SID cannot be reused and require reauthorization.
