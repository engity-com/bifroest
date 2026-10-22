---
description: How to store Bifröst sessions on the local filesystem.
---

# Filesystem session

This variant of [session](index.md) is stored on the same local filesystem on which Bifröst is running.

## Properties

<<property("type", "Session Type", default="fs")>>
Can be set to `fs` to enable the filesystem session. If absent, `fs` is always chosen by default.

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="30m")>>
For how long a session can be idle before it will forcibly be closed and disposed and can therefore not be used again. This can extend by actions of the client (regular interactions or keep alive) across all of client's connections.

<<property("maxTimeout", "Duration", "../data-type.md#duration", default=0)>>
The maximum duration of a session before it will forcibly be closed and disposed regardless whether there are actions or not.

<<property("maxConnections", "uint16", "../data-type.md#duration", default=0)>>
The maximum amount of parallel connections of one session. Each new connecting connection will be instantly closed.

<<property("storage", "File Path", "../data-type.md#file-path", default='<os specific>')>>
Where the session information is stored locally.

Only one Bifröst process can open a filesystem session repository at a time. A non-blocking operating-system lock is held for the repository lifetime; startup fails if another process already owns the same storage or if the lock state cannot be determined safely. Session state updates use atomic file replacement so a process interruption cannot expose a partially written token.

The storage must not overlap an enabled audit log's journal, signing identity, encryption public-key file, or local SFTP target `known_hosts` and identity files. Bifröst resolves existing parents and symbolic links before checking these paths and rejects unsafe configurations during startup.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/sessions`
* macOS: `/Library/Application Support/Engity/Bifroest/sessions`
* Windows: `C:\ProgramData\Engity\Bifroest\sessions`

<<property("fileMode", "File Mode", "../data-type.md#file-mode", default="0600")>>
All files/directories inside the session storage will be stored with this mode. Directories will always get the executable bit.

## Session association groundwork

!!! warning "Server primitive; not yet connected to browser or SSH login"
    The repository now provides an optional identity/target association API for the planned shared SSH/HTTP session selection. Current login paths still use their existing selection logic; enabling HTTP does **not** yet enable shared browser sessions. The HTTPS transport still returns 501 for valid browser flow paths. There is no browser RememberMe implementation or new configuration flag here.

`ResolveAssociatedSession` accepts a **server-verified** identity, a flow, unchanged remote-client metadata and a side-effect-free target resolver. The identity's issuer and subject form the ownership key; a configurable principal, a possibly empty `remote.user`, or a known session ID cannot substitute for that key. This is a trusted server API, **not** credential verification or a client-facing endpoint. Login adapters must only call it after real credential/signature verification, never for an unsigned SSH key probe or browser-supplied identity claims.

For a candidate session, the resolver receives that candidate's flow and ID. Target descriptors can therefore evaluate names such as a Kubernetes pod's `bifroest-{{ .session.id }}` against the **existing** session rather than allocating a new one first. `NewTarget` creates a SHA-256 digest from a versioned canonical encoding of explicit server-resolved environment fields. Environment adapters must supply the effective backend/account and all relevant target selectors; the digest does not resolve those fields itself, grant access, encrypt secrets or represent a concrete container ID. Credentials and incidental transport/browser-selection fields do not belong in the descriptor.

The filesystem repository serializes selection/creation per stable identity and flow, with cancellable waits. It selects only a matching, still-valid, bound session and optionally checks environment compatibility. A new selection persists its metadata, authorization token and association under the repository write lock before returning. Reuse does **not** replace authorization/refresh tokens, update access times or attach connections. The future adapter must still perform its authorization, token/refresh coordination, connection-limit/revocation checks and connection registration. Selection is not a lease against concurrent disposal.

The optional `sa` file lives beside the existing session files. It contains exactly `schema`, `issuer`, `subject` and the target digest, with schema `bifroest-session-association-v1`. Reads are bounded to 16 KiB, reject nonregular/symlink or changing files, and reject unknown/duplicate fields, wrong types, malformed digests, unknown versions and trailing content. Associations are immutable; an explicit first binding is limited to a new inactive session without environment state. Existing metadata updates do not overwrite this separate record. Session directory creation cannot replace an existing directory on an ID collision.

Legacy sessions without `sa` remain readable and usable by existing SSH login paths. The new selector does not automatically claim or migrate them, even when client names or opaque tokens happen to match. It rejects anonymous identity-based reuse outright: anonymous sharing still needs a separately verified possession proof, which this primitive does **not** implement. Browser domain/slug/target resumption grants are also separate and remain pending.

Malformed or unknown association state is preserved for operator inspection, including when ordinary session metadata is broken/missing or an environment token is absent; Docker/Kubernetes resources can exist outside the session directory. An invalid entry in the selected flow aborts selection rather than silently skipping or replacing potentially owned state. Automatic cleanup recognizes `sa` and does not delete it as an unexpected file. Do not rely on an older binary's automatic repair understanding this new sidecar during downgrade. No existing authorization, environment, audit or evidence format is rewritten by adding this API.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
