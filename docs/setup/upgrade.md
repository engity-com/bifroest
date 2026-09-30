---
description: Changes to account cleanup when upgrading Bifroest.
---

# Upgrade notes

## Local environments and existing sessions

Persisted Linux `local` environment tokens written before the cleanup-token format with a `version` field are **not migrated**. Even if an old token contains `user.deleteOnDispose`, its previous account, home-directory and process cleanup decisions are not run by the new version. When such a session is disposed, its token is removed; the account, home directory and processes may remain. This is intentional to avoid deleting an account using an old, insufficiently verified identity snapshot.

Before upgrading, identify accounts whose cleanup depended on those existing sessions. If cleanup is needed, complete it before the upgrade or reconcile the remaining accounts manually after verifying their current identity, home ownership and active sessions. Do not assume that changing the new configuration will clean up sessions whose tokens were already written.

For **new** sessions, configure the top-level [`deleteOnDispose`](../reference/environment/local.md#property-deleteOnDispose) and [`killProcessesOnDispose`](../reference/environment/local.md#property-killProcessesOnDispose) settings for the desired policy. The former defaults to `false`; the latter defaults to `{{ .user.managed }}`. Legacy nested `dispose.*` settings must be replaced with the current top-level settings.

On Linux, process cleanup uses `pidfd_open` and `pidfd_send_signal`. It requires a kernel with `pidfd_open` support (Linux 5.3 or newer) and a security profile that permits both syscalls. If either call is unavailable or blocked, process cleanup fails closed and an account deletion waiting on it is not performed. Disabling `killProcessesOnDispose` for new sessions avoids this prerequisite, but may leave processes running when their account is removed.
