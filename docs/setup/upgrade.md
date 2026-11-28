---
description: Actions and behavior to consider when upgrading Bifröst from v0.7.8.
---

# Upgrade from v0.7.8 to <<release_name()>> {: #upgrade-notes .upgrade-notes-headline data-release="<<release_name()>>" data-baseline="v0.7.8" }

These notes apply to an upgrade from any v0.7.x release to <<release_name()>>. They document upgrade actions and behavior changes, not release notes. Patch releases within the new series share these upgrade notes.

<p id="upgrade-predecessor" data-release="<<release_name()>>" hidden></p>

## Session storage

### `session.storage` (filesystem)

The filesystem session repository now holds an exclusive operating-system lock. Before starting the upgraded Bifröst, stop every process using the same storage: only one process can open it at a time.

The lock file, `.<storage-name>.bifroest.lock`, is created next to the **resolved** storage directory. Check that its parent directory and any existing lock file are writable. Storage symlinks resolve to the same lock; a symlink pointing to a missing directory prevents startup.

### Existing sessions: no import

**Sessions created by v0.7.8 are not imported or reused.** They lack the persistent runtime ownership required by the upgraded service. All users must authenticate again; old saved SSH access and browser RememberMe bindings cannot bypass this boundary.

Rejecting an old session does **not** authorize cleanup of its container, Pod, local account, home directory, processes or data using the new configuration. Unassigned session records and backend resources remain preserved for operator review, not automatic migration or disposal.

Unscoped automatic orphan scans are disabled: flow labels, missing session IDs or a terminated Pod do not prove ownership. `cleanOrphan` does not override this boundary. Cleanup of sessions with a known runtime owner remains active.

Before upgrading:

1. Identify backend resources belonging to old sessions and back up needed workload data. Complete any required cleanup using the old version, or plan to verify ownership and reconcile resources manually afterward.
2. Stop the old instance and back up configuration and session storage.
3. Start the upgraded service and test a fresh login over every enabled transport. A new login creates a new session rather than adopting an old backend.

### Subsequent restarts and runtime metadata

Sessions created by the upgraded service can be reused after a restart only when their immutable ownership matches the accepted runtime state. Credential, identity, account and target checks still apply. Changed or unproven ownership denies reuse without assigning cleanup to a new provider.

The current restart proof supports `dummy` and `management` environments with `none`, inline `simple`, or OIDC authorization. OIDC also compares resolved client settings and discovery metadata. External environment providers, `local`/`htpasswd` authorization and file-backed `simple` credentials or user CAs currently require a new session after every process restart, even if their configuration text is unchanged. Their old resources are not automatically reconciled through the new provider.

Keep the private `.<storage-name>.bifroest-runtime-key` and `.<storage-name>.bifroest-runtime-state` files beside the resolved storage directory in a consistent, stopped backup. Session ownership (`ro`) and revocation (`rr`) records are part of session storage; these files contain no additional provider configuration copies. Protect the comparison key like other credentials.

A leftover `.<storage-name>.bifroest-runtime-pending` file indicates an unfinished authority or revocation write and **blocks startup**. Invalid state or a missing key for existing state also blocks startup. Do not delete individual runtime files to force recovery: inspect the failure and restore a complete, consistent backup, reconciling later revocations, or deliberately use new empty session storage and require fresh authentication. Preserve and reconcile old backend resources separately.

### `session.maxTimeout`

If set, the maximum lifetime now counts from session creation rather than last access. Check active sessions and this setting before upgrading: some sessions may expire earlier or immediately.

This does not make v0.7.8 sessions eligible for import.

## Flows

### `flows[].name`

Flow names must be unique, may not be `.` or `..`, and may not exceed 255 bytes. Correct existing names that violate these rules before starting the upgraded version, or configuration validation will fail.

## Authorizations

### RememberMe

RememberMe now defaults to `forbidden` for `local`, `simple`, `htpasswd` and `oidcDeviceAuth`. To allow registration and reuse for **new sessions**, set `rememberMe: allowedAndEnabledByDefault` on the relevant authorization. This does not import remembered access from v0.7.8 or override restart ownership checks. Ordinary configured SSH keys remain valid. See [RememberMe](../reference/data-type.md#rememberme).

### OIDC Device Auth

OIDC now defaults to `forceDisposeSessionOn: lostAccess` and `refreshToken.mode: proactive`. Before upgrading, ensure your identity provider issues refresh tokens for the configured client and scopes (often requiring `offline_access`). Otherwise, new OIDC logins will be rejected. Bifröst does not add provider-specific scopes automatically.

The existing-session boundary above also applies to OIDC: old grants are not adopted or disposed through the new provider. Users must authenticate again.

To temporarily allow **new logins** without refresh-token enforcement while configuring your identity provider, explicitly set **both** properties in the OIDC authorization. This does not preserve or import old sessions:

```yaml
forceDisposeSessionOn: never
refreshToken:
  mode: never
```

See the [Device Authorization reference](../reference/authorization/oidc/device-authorization.md) for the full configuration and examples.

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

Containers and Pods belonging to v0.7.8 sessions are not adopted. Neither a new login nor housekeeping may delete them using an unproven provider assignment. Changing lifecycle labels or annotations does not establish ownership or upgrade the IMP binary.

**Before starting the upgraded Bifröst**, back up any needed container-local data, anonymous Docker volumes, and Pod-local ephemeral data. Complete cleanup with the old version or reconcile verified resources manually; do not expect the upgraded service to dispose them automatically. Persistent volumes have their own lifecycle. See the [Docker](../reference/environment/docker.md#execution-lifecycle-and-upgrades) and [Kubernetes](../reference/environment/kubernetes.md#execution-lifecycle-and-upgrades) details.

#### Linux execution-scoped signals

If you use execution-scoped signals in Linux containers or Pods, check for Linux 5.3 or newer and a seccomp profile allowing `pidfd_open` and `pidfd_send_signal`. Otherwise signal requests fail.

### Linux (`local`)

#### Existing session cleanup tokens

Persisted `local` sessions from v0.7.8 and their cleanup decisions are **not imported**. The upgraded service does not assign their accounts, home directories or processes to the new environment provider.

Before upgrading, identify accounts whose cleanup relied on existing sessions. Complete any needed cleanup before the upgrade, or afterward verify account identity, home ownership, and active sessions before reconciling them manually. Changing the new configuration cannot restore cleanup decisions in old tokens.

#### `environment.dispose.*`

v0.7.8 accepted these Linux `local` settings, which the upgraded version rejects if explicitly set:

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

Run Bifröst as LocalSystem for S4U session process startup, and check the selected account's permissions. S4U does not provide that account's network credentials or EFS access; check workloads that previously relied on the service identity. The no-import boundary also applies to all v0.7.8 Windows `local` sessions.
