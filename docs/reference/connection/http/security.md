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
| Web access expires after 10 minutes | New connections and standalone HTTP management operations require fresh authentication or an explicit saved-access action. An existing terminal or pre-expiry admitted management channel can continue within its original scope and current authorization. Keepalive does not renew the credential. Locally loaded recordings remain available. |
| Session idle/maximum timeout | Remains authoritative for SSH and browser access. Terminal and management keepalive do not extend it. |
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

Each management tab owns a separate, same-origin channel admitted with its web
credential before expiry. Requests on it retain the admitted actor and scope;
there is no reusable replacement bearer or HTTP-header bypass. Requests execute
serially under that connection's quota lease, with at most four pending requests.
Responses are collected in fixed-size bounded blocks, not one retained object
per network fragment. Partial responses are discarded on cancellation or error.
Current authorization, revocation, target compatibility and per-operation
permissions, audit and Recording policies remain enforced. Confirmation grants
are one-use and bound to their own channel as well as the actor and target.
Closing the channel cancels its operations. It neither starts a shell nor
reconnects automatically. Loss of an action result still means an uncertain
outcome, not permission to repeat it.

Browsers automatically attach applicable same-origin cookies to WebSocket
upgrades. Bifröst does not use them for authentication: only the explicit
access proof in the channel's opening frame can admit it. Ordinary JSON API
requests continue to omit browser credentials.

Artifact download additionally requires
[`allowArtifactTransfer`](../../environment/management.md#property-allowArtifactTransfer).
The first active view loads only its authorized metadata, not recording content.
**Open recording** explicitly downloads the selected original into this tab.
No header or content verification starts on open. Use the playbar's **Verify**
action explicitly; playback remains locked until full verification succeeds.
During that check the signed header determines encryption. A matching previously
verified tab key can be reused; otherwise verification options accept a local key
and passphrase. Recipient fingerprints are derived locally. Full verification
prepares playback or an audit-event list; **Play** remains a separate local action.
Verification, decryption, export preparation and playback run locally. Private
decryption keys and decrypted content are not uploaded or persisted by the app.
Explicitly saved files remain on the user's machine after logout.

Only after successful private verification does the management tab retain its
decryption key and passphrase in volatile memory. Its Recordings and Audit logs
pages share that cache, but unrelated tabs, accounts and login grants do not.
A newly selected file takes precedence over the cached key; failed candidates
do not replace the last verified key. **Forget decryption key**, authoritative
logout, closing the management tab or reloading releases the cache. Owned
passphrase bytes are wiped; JavaScript strings/immutable Blobs remain subject to
browser garbage collection, so this is not a physical-memory-erasure guarantee.
The cache is never stored in IndexedDB, localStorage, URLs or RememberMe.

The default audit-event overview is operational **server-reported data**, not
independent producer/journal evidence. It loads at most 20 records per page;
source access still requires `allowArtifactTransfer`, and forced-command metadata
ceilings cannot acquire this content capability. The native reader indexes only
public record metadata in bounded private temporary files, pins selected source
handles, and authenticates only selected records. It does not verify the complete
producer chain or download it to the browser. Source/cursor/filter/actor binding
and final audit/capture completion still govern publication. Unverified event
shortcuts are not canonicalized from server-reported flow metadata.

Private output remains an explicit actor/source-owned opt-in through the audit
grid/dialog eye, not a saved origin-wide detail preference. Encrypted context is never
decrypted server-side. An exact clear-flow selector can narrow a public overview
without enabling a private export; unknown encrypted context cannot match that
selector. Hidden fields are not empty values for negative/empty predicates.

The toolbar certificate action opens verification options; confirming them
explicitly starts a fresh whole-audit transfer or rechecks the selected downloaded
snapshot. Only its local event view is built from successfully verified
local export bytes. That view keeps a bounded offset/time index and materializes
one page, not one JavaScript object for every event. Its filtering/paging remain
local to those bytes. Initial indexing shares the same abortable operation and
must finish before a new local result is published. The `123` toolbar action
returns to server-reported data, never claims that those data are locally checked.
Breadcrumb navigation retains event lists without replaying their transfer;
details have no standalone X. Producer identity still needs an independent pin.

Outside audit events, the eye is an origin-scoped presentation preference, not an
authorization/encryption switch. The audit eye instead explicitly selects private
fields for that owned view and its local export. It is not persisted, inherited
from the presentation preference, or rebound to another actor/source. Server reads
include only private clear context already permitted by artifact-content policy;
encrypted fields require local verification/decryption. Local eye changes reuse
owned bytes, retain list selection, and never issue a transfer or server query.
No eye upgrades credentials, uploads keys or confirms a signing identity.

Session IDs lead their table. Configured source links can narrow Recordings and
events by exact flow/session selectors, with normalization and actor/filter/MAC
cursor binding. Forced metadata projections withhold the added source association.
Relationship actions use only permitted row/detail fields, never a route filter
as proof of an event's session/flow. Unknown IDs/flows have no guessed jump target;
recording shortcuts remain opaque until local verification can canonicalize them.
Server-reported and locally checked event details share one layout while retaining
their provenance distinction. Target reads still reauthorize; no navigation link
confers a grant or implicitly searches foreign archives.

Live shell titles are bounded, control-/bidi-formatting-free text attached only
to the owning connection tab. They are not trusted identities or navigation
targets. The browser document title, playback titles and unrelated tabs are not
controlled by recorded or live shell output.

Seeking replays the verified local output prefix, including recorded resizes;
display scaling and fullscreen do not resize a live terminal or alter recorded
dimensions. Player shortcuts are focus-scoped. Optional OS media controls bind
only after interaction with an active player and release on deactivation or
close. They expose a generic player title, not recording or account metadata.

The optional signing-ID field is prefilled from the selected signed header and
is editable when identity validation is enabled. Prefilling does not establish
independent trust: the default status explicitly distinguishes checked integrity
from independently confirmed identity. Use a separately obtained producer ID
when independent identity confirmation is needed. Valid signatures do not prove that newer
records were not withheld. The application code also comes from that server:
use the [CLI](../../cli/verification.md) in a separately trusted environment when
independent verification matters.

The catalog is server-reported metadata, not independent evidence. Its filters
apply across the captured inventory, with newest recordings first. New recordings
can contain the original requesting name; older or encrypted recordings may not
expose identity details. Missing names and target accounts are not reconstructed
from current sessions or authorization.

Recording listing, searching and complete verification are separate operations.
Normal listing indexes authenticated header/seal/setup metadata without hashing,
decoding or verifying intervening contents. The metadata type is not a full
verification result, and its cache never populates the content-verification cache.
Only the selected page is independently reopened and fully checked before
publication; a corrupt unselected body is the concern of an explicit full check,
not an implicit prerequisite for every other page.

Private metadata caches live outside evidence directories, bind inode/file ID,
size, mode, mtime and change stamps, and verify their cached images' digests. They
reuse file-derived images only on supported change-stamp platforms. Windows
file times can conceal completed same-size writes with restored mtime, so Windows
uses fresh, provisional metadata images and removes them after each read. It
neither grants host rights nor enables/forces a filesystem change journal. This
does not turn normal queries into full recording/journal verification. The caches
are bounded and removed on owner shutdown, store no credentials/decryption keys
or decrypted encrypted context, and never authorize a row. Recording metadata
entries may contain setup context already clear in that source; audit indexes
contain only public fields/positions, never private payloads. A cache miss or
eviction rebuilds metadata only, not complete recording contents. A private
temporary binary-ID inventory fixes each Recording query's member set and is
digest-checked and removed on every outcome. Only a page plus lookahead is kept
for sorting/filtering; no whole inventory is materialized in RAM.

Explicit Recording **Verify all** bypasses the verified cache and reads every
container again. Its full/outer counters distinguish clear private-content checks
from encrypted envelope-only checks. It establishes no independent browser trust.
An independent, single bounded verification/transfer worker shares the existing
channel admission and four-pending-request limit, so it does not block operational
reads or acquire a new bearer/socket/connection quota. Cancellation and native
session policies cover both workers. No read is retried automatically.

Clients opt into count-only progress with `"progress":"counts-v1"` in the
`bifroest-management.v1` open frame. Correlated progress frames contain only
`type`, `requestId`, `phase`, `completed` and `total` (`-1` means unknown). Clients
without this capability receive the existing response/body/completion framing.
Progress does not release rows or acknowledge final audit/capture/sealing.
Final matching-row counts reach the grid only with their correlated, successfully
completed page; scan counts alone never enable paging or opening a result.
Forced-command read ceilings receive phases without whole-archive counts, so a
restricted flow/user projection cannot learn other inventory totals this way.
Remote phases cannot claim local decryption, integrity verification or indexing;
those statuses originate only in the owned browser pipeline.
Complete structured results still require the shared driver's successful final
audit and recording completion. Artifact transfers still require their exact
Go-verified selectors/data-end/post-driver completion and local evidence checks.

Auditlog-source scans, artifact transfer, local evidence verification and local
audit indexing/filtering also report owned, cancellable progress. Long scans,
transfers and local verification do not have aggregate execution deadlines.
Transport startup, WebSocket liveness, bounded writes/cancellation acknowledgement
and native session idle/maximum lifetimes remain separate and authoritative.
No refresh click is required to continue ordinary verification work.

Failed structured management reads are logged on the server with their backend
cause, operation and connection; WebSocket reads also include channel and request
IDs. Bearers and request bodies are not logged. The browser receives only a
generic failure, not backend paths or errors.

The native Community filter panel supports one column predicate plus quick
search. All remote predicates are applied before pagination and remain bound to
their cursor, actor and scope. Hidden or unavailable metadata cannot match
negative or empty-value predicates. Filters never expand forced-command rights
or verification budgets.

## Practical limits

| Browser operation | Limit |
| --- | --- |
| Open terminal/management tabs | 8 per window, in addition to server session quotas |
| Terminal sockets | 64 total, 8 per direct peer IP |
| Private-key import | One PEM/OpenSSH key, at most 64 KiB; optional matching OpenSSH certificate at most 12 KiB |
| Key algorithms | Ed25519, RSA 2048–8192, NIST P-256/P-384/P-521; no DSA or hardware/security-key formats |
| Artifact payload | 64 MiB in tab memory; use native tools for larger artifacts |
| Recording catalog | Metadata-index listing/search; at most 20 selected contents checked per page, one lookahead metadata candidate. Directory batches of 128; process-local disk metadata cache at most 128 MiB / 16,384 entries per repository (4 KiB per entry); no aggregate archive count/execution deadline. Each individual content check remains bounded to 128 MiB container and canonical/decoded Cast. Private temporary inventory uses 16 bytes per Recording ID. |
| Audit overview | At most 20 selected records, up to 21 retained source leases; each segment at most 17 MiB. Public-metadata cache at most 128 MiB / 128 entries plus one in-progress index build bounded to 64 MiB; no private payloads or whole-journal browser download. Cache eviction may rebuild public metadata. |
| Recording playback | 100,000 events, at most 512 columns, 256 rows and 32,768 cells |
| Local audit-event view | At most 250,000 records / 64 MiB of verified JSONL; bounded typed index, at most 1 MiB per event line and 20 displayed rows per page |

Encrypted PKCS#8, PPK and multi-key files are not supported. Browser terminals
provide shells, not SFTP or port forwarding. OS/browser shortcuts that never
reach the page cannot be captured by the terminal.

Request-rate and bounded-buffer limits reject overload rather than dropping
terminal input or retrying actions. A TCP proxy's connections share its direct
peer IP for admission limits. Missing WebGL falls back to DOM rendering without
reconnecting; font or display scaling can affect line rendering in that fallback.
