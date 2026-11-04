---
description: Understand browser access, saved logins, management permissions and practical limits.
---

# HTTP security and limits

This page explains the boundaries of [HTTPS access](../http/index.md). For a first
connection, follow the [browser access guide](../../../guides/browser-access.md).

## TLS and deployment

* Bifröst terminates TLS directly. An HTTP reverse proxy cannot terminate TLS
  on its behalf; use TCP pass-through if a proxy is needed.
* The requested host must be a configured domain and agree with TLS server-name
  selection. API calls and terminal upgrades require the same HTTPS origin,
  including its port. Forwarded headers do not replace these checks.
* The application does not support cross-origin API access or iframe embedding.
  Keep its canonical paths; do not publish it beneath a rewritten path prefix.
* TLS and ACME keys must be separate from SSH and audit keys. Public assets and
  custom files cannot overlap private service storage.
* Custom JavaScript is trusted application code. A malicious script can act with
  the user's access, even when browser keys are non-exportable.

Protect the service account, configuration, browser assets and backups as
described in [Security and trust](../../../security.md).

## Authentication and sessions

Password, interactive/device and SSH-key logins use the configured authorizer,
not a separate web account. A flow link or known session ID does not grant access.
Discovery describes possible methods without user-account, key, session or IdP
lookups. The server still enforces current host and user requirements at login.
Imported private keys and passphrases stay in the current browser tab; only the
public key and a fresh signature are sent to authenticate.

SSH and browser connections can reuse the same compatible session and workload
after authentication. Their permissions remain connection-specific. A new tab
starts a new shell, not a second view of an existing process. Reload discards the
local tabs; another login or explicit saved-access action starts a fresh shell.
Switching existing tabs only restores each tab's original access scope in the
URL, preserving aliases; it does not authenticate, reconnect or start work.

| Limit | Effect |
| --- | --- |
| Web access expires after 10 minutes | New connections and management reads require fresh authentication or an explicit saved-access action. The management view offers **Sign in again**; existing terminals and already loaded local recordings remain available. |
| Session idle/maximum timeout | Remains authoritative for SSH and browser access. Terminal keepalive does not extend it. |
| Closed browser tab | Disconnects that execution; does not dispose the shared session or workload. |
| Explicit logout | Revokes that web access and its linked connections. For remembered access, all web access linked to that binding is revoked. Other browser bindings and SSH connections are not logged out. |

A lost logout or session-action response is not proof of success. The UI reports
an uncertain result rather than repeating the action automatically. Inspect the
target before deciding what to do next.

## RememberMe

RememberMe starts only after explicit opt-in. It persists independent,
non-exportable signing and encryption keys in IndexedDB, not a password or the
imported SSH key. Resuming requires a fresh proof and current authorization.
The default unused timeout is [six hours](../http/index.md#rememberme-property-idleTimeout);
shorter session limits and revocation still apply.

Authorizers can impose additional limits. In particular,
[Local authorization](../../authorization/local.md) has platform and PAM
prerequisites. Unsupported account-policy checks require a regular login.

Removing only local browser data does not revoke server-side access. Use explicit
logout or the saved-access revocation action first when possible. Non-exportable
keys are not hardware binding or protection against malicious same-origin code
or complete browser-profile copies.

Theme, last successful requesting name and last accepted editable keepalive
interval are separate UI preferences. They do not authenticate or start login.

## Management and evidence

A [Management flow](../../environment/management.md) provides session inspection,
disconnect/dispose actions and recording/audit catalogs. It uses the same
management permissions as SSH, without another administrator role.

Authorized-key restrictions still apply. Supported forced commands include
`version`, `flow ls`, `audit ls`, `session ls`, and exact-ID `session show`,
`session disconnect` and `session dispose`. Their filters and permitted fields
remain restricted. Other forced commands do not gain a browser equivalent.
Action-only credentials do not also gain list or inspection rights.

Artifact download additionally requires
[`allowArtifactTransfer`](../../environment/management.md#property-allowArtifactTransfer).
The first active view loads only its authorized metadata, not recording content.
**Open recording** explicitly downloads the selected original into this tab.
**Check and open** uses your protection and trust choices for full verification
and player preparation; **Play** remains a separate local action.
Verification, decryption, export preparation and playback run locally. Private
decryption keys and decrypted content are not uploaded or persisted by the app.
Explicitly saved files remain on the user's machine after logout.

Seeking replays the verified local output prefix, including recorded resizes;
display scaling and fullscreen do not resize a live terminal or alter recorded
dimensions. Player shortcuts are focus-scoped. Optional OS media controls bind
only after interaction with an active player and release on deactivation or
close. They expose a generic player title, not recording or account metadata.

Obtain expected producer IDs and recipient fingerprints independently. A server's
own metadata is not a trust anchor. Valid signatures do not prove that newer
records were not withheld. The application code also comes from that server:
use the [CLI](../../cli/verification.md) in a separately trusted environment when
independent verification matters.

The catalog is server-reported metadata, not independent evidence. Its filters
apply across the bounded inventory, with newest recordings first. New recordings
can contain the original requesting name; older or encrypted recordings may not
expose identity details. Missing names and target accounts are not reconstructed
from current sessions or authorization.

## Practical limits

| Browser operation | Limit |
| --- | --- |
| Open terminal/management tabs | 8 per window, in addition to server session quotas |
| Terminal sockets | 64 total, 8 per direct peer IP |
| Private-key import | One PEM/OpenSSH key, at most 64 KiB; optional matching OpenSSH certificate at most 12 KiB |
| Key algorithms | Ed25519, RSA 2048–8192, NIST P-256/P-384/P-521; no DSA or hardware/security-key formats |
| Artifact payload | 64 MiB in tab memory; use native tools for larger artifacts |
| Recording catalog | At most 1,024 sealed recordings; bounded 128 MiB verification budgets and a four-second query deadline. Filters do not bypass these inventory limits. CLI UUID-paged listing remains available for larger archives. |
| Recording playback | 100,000 events, at most 512 columns, 256 rows and 32,768 cells |

Encrypted PKCS#8, PPK and multi-key files are not supported. Browser terminals
provide shells, not SFTP or port forwarding. OS/browser shortcuts that never
reach the page cannot be captured by the terminal.

Request-rate and bounded-buffer limits reject overload rather than dropping
terminal input or retrying actions. A TCP proxy's connections share its direct
peer IP for admission limits. Missing WebGL falls back to DOM rendering without
reconnecting; font or display scaling can affect line rendering in that fallback.
