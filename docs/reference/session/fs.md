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

!!! warning "Partial login integration; no browser login yet"
    Primary Simple, htpasswd and Local logins now use the identity/target association selector with built-in environments and the filesystem repository. This includes passwords, keyboard-interactive credentials and verified configured keys/certificates where the authorizer supports them. Fresh OIDC and Bifröst-delegation logins still use their previous allocation paths; OIDC grant/refresh coordination remains pending. Enabling HTTP does **not** yet enable browser login, terminals or RememberMe: valid browser flow paths still return 501.

`ResolveAssociatedSession` accepts a **server-verified** identity, a flow, unchanged remote-client metadata and a side-effect-free target resolver. The identity's issuer and subject form the ownership key; a configurable principal, a possibly empty `remote.user`, or a known session ID cannot substitute for that key. This is a trusted server API, **not** credential verification or a client-facing endpoint. The optional `AuthenticatedSessionResolver` adapter hook is called only after primary credentials/signatures were checked. The SSH adapter re-evaluates both raw-key and certificate authorization after possession proof; built-in key probes do not allocate sessions, and OIDC remembered-key probes do not refresh credentials or report access loss.

For a candidate session, the resolver receives its flow, ID and immutable creation metadata. Target templates may use `.session.id`, `.session.flow`, `.session.created.*` and their `.authorization.session.*` equivalents. A new candidate uses prospective creation metadata with the exact timestamp subsequently persisted; no placeholder session is created. Mutable session fields such as state or last access are not suitable target selectors and are rejected in this context. Names such as a Kubernetes pod's `bifroest-{{ .session.id }}` are evaluated against the **existing** candidate, not a newly allocated ID. `NewTarget` creates a SHA-256 digest from a versioned canonical encoding of explicit server-resolved fields; it does not grant access, encrypt secrets or identify a concrete container by itself.

Built-in `SessionTargetResolver` implementations do not provision environments, read SSH private keys, pull images, create namespaces/secrets or open target transports. SSH selection uses the parsed address (including default port and case-insensitive DNS name), trimmed account and forwarding settings; absolute and relative DNS names remain distinct. Local selection renders the account requirements and reads existing account identity without creating/modifying it; Unix reuse also checks the stored UID, and Windows retains its SID checks. Docker selection includes its configured backend, OS/architecture, image, execution account/directory, networks, mounts/volumes, capabilities, privilege, DNS, commands and forwarding setting. Kubernetes additionally selects cluster endpoint, effective namespace, candidate pod name, service account and group. Management selection includes its existing credential/artifact-transfer permissions, without adding a new role. Credentials, image-pull secrets, browser domain/slug and incidental client metadata are excluded unless a target template explicitly uses such metadata to choose the environment. Operational timeouts, banners and cleanup scheduling do not define a target.

The filesystem repository serializes selection/creation per stable identity and flow, with cancellable waits. It selects only a matching, still-valid, bound session and optionally checks environment compatibility. Integrated static-authorizer logins additionally require the existing opaque authorization token to match; absent/replaced credentials are not overwritten. Existing environment state must remain compatible; a matching bound session can be joined before environment credentials have been provisioned. A new selection persists its metadata, authorization token and association under the repository write lock before returning. Selection itself does **not** update access times or register connections. Existing SSH connection-limit, revocation, execution and recording checks still apply after selection. Selection is not a lease against concurrent disposal. OIDC refresh tokens are never replaced through this hook; OIDC login integration is still pending.

The optional `sa` file lives beside the existing session files. It contains exactly `schema`, `issuer`, `subject` and the target digest, with schema `bifroest-session-association-v1`. Reads are bounded to 16 KiB, reject nonregular/symlink or changing files, and reject unknown/duplicate fields, wrong types, malformed digests, unknown versions and trailing content. Associations are immutable; an explicit first binding is limited to a new inactive session without environment state. Existing metadata updates do not overwrite this separate record. Session directory creation cannot replace an existing directory on an ID collision.

Legacy sessions without `sa` remain readable and usable through existing remembered-key SSH paths. New primary selection does not automatically claim or migrate them, even when client names or opaque tokens happen to match. Existing bound associations are also checked during remembered-key/token lookup, so those lookup paths cannot bypass identity/target matching. Third-party adapters or environment/session repositories without the optional capabilities retain their previous primary selection behavior; no target semantics are guessed for them. Anonymous identity-based reuse is rejected: independent anonymous possession proofs and browser domain/slug/target resumption grants remain pending.

Malformed or unknown association state is preserved for operator inspection, including when ordinary session metadata is broken/missing or an environment token is absent; Docker/Kubernetes resources can exist outside the session directory. An invalid association-bearing entry in the selected flow aborts selection rather than silently replacing potentially owned state. Corrupt **unbound legacy** entries are skipped without deletion and remain available to management diagnostics, so operators can still log in to inspect them. Automatic cleanup recognizes `sa` and does not delete it as unexpected content. Do not rely on an older binary's automatic repair understanding this sidecar during downgrade. Existing authorization, environment, audit and evidence formats are not rewritten.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
