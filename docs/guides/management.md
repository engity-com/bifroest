---
description: Configure separate workload and management flows, connect an administrator's workstation and inspect live state.
---

# Manage a Bifröst host remotely

This Linux example adds a dedicated management flow alongside a local-account workload flow. Workload and administration events go to different audit logs. The management connection can inspect metadata without downloading signed evidence.

Start with an installed [Bifröst host](../setup/on-host.md), a local account allowed to use the workload flow, and a separate SSH key for administrator login. The paths below assume the host configuration uses `/etc/engity/bifroest` and `/var/lib/engity/bifroest`. Other platforms have [different defaults](../reference/cli/usage.md#configuration).

## Examples

### Configure remote administration

1. Provision the administrator's **public login key** in `/etc/engity/bifroest/management_authorized_keys`. Keep the corresponding private key on the workstation as `~/.ssh/bifroest-management`. Make the server file readable by the Bifröst service user and writable only by the administrator responsible for configuration.

2. Configure two audit logs and two flows:

    ```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
    auditlogs:
      workload:
        identityFile: /etc/engity/bifroest/workload-signing-key
        directory: /var/lib/engity/bifroest/workload-audit
        recording:
          enabled: true
          directory: /var/lib/engity/bifroest/workload-recordings

      administration:
        identityFile: /etc/engity/bifroest/administration-signing-key
        directory: /var/lib/engity/bifroest/administration-audit
        recording:
          directory: /var/lib/engity/bifroest/administration-recordings

    flows:
      - name: administration
        auditlog: administration
        requirement:
          includedRequestingName: ^management$
        authorization:
          type: simple
          entries:
            - name: management
              authorizedKeysFile: /etc/engity/bifroest/management_authorized_keys
        environment:
          type: management
          includingCredentials: false
          allowArtifactTransfer: false

      - name: local
        auditlog: workload
        requirement:
          excludedRequestingName: ^management$
        authorization:
          type: local
        environment:
          type: local
          name: "{{.authorization.user.name}}"
          portForwardingAllowed: false
    ```

    `management` selects only the administration flow. Other requesting names can use local-account authorization. Journal and Recording paths are separate, and each auditlog has its own signing identity. The default strict failure policy applies.

3. Restart Bifröst using the host's service manager. On first start with empty repositories, Bifröst creates the configured signing keys and storage. Retain existing identity and repository files on subsequent starts.

4. Obtain the host's SSH public key through a trusted provisioning channel and install its matching `known_hosts` entry on the workstation. Add a login alias:

    ```sshconfig title="Administrator workstation: ~/.ssh/config"
    Host bifroest-admin
        HostName bifroest.example.org
        User management
        IdentityFile ~/.ssh/bifroest-management
        UserKnownHostsFile ~/.ssh/known_hosts
    ```

    Replace the hostname with the actual host. The integrated client requires an already trusted host key; it does not accept an unknown key automatically.

5. Inspect the server from the workstation:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin flow ls
    bifroest @bifroest-admin flow show administration --format=yaml
    bifroest @bifroest-admin audit ls
    bifroest @bifroest-admin audit events administration --limit=20
    ```

    Settings are redacted. Metadata and public event queries work with `allowArtifactTransfer: false`. This does not make the flow read-only: an unrestricted management login can also disconnect and dispose of sessions.

### Find a workload session and its Recording

1. Using a standard SSH client and an allowed host account, open a workload shell:

    ```shell title="Workload terminal"
    ssh alice@bifroest.example.org
    ```

    Replace `alice` with the actual requesting username. Leave this shell open for the next step.

2. Inspect that session from the administration workstation:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin session ls --flow=local --user=alice --format=json
    bifroest @bifroest-admin session show SESSION_UUID
    ```

    Replace `SESSION_UUID` with an ID from the listing. The flow filter excludes the administration session itself.

3. In the workload shell, print a marker and exit:

    ```shell title="Workload terminal"
    printf 'recording-check\n'
    exit
    ```

4. Find the sealed Recording and inspect its metadata:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin recording ls workload --limit=20
    bifroest @bifroest-admin recording show workload RECORDING_UUID --format=json
    ```

    Use the returned Recording UUID, which is distinct from the session UUID. Listing order is by Recording ID, not start time; use the reported timestamps when choosing a Recording.

5. The same metadata query is available through a standard SSH client:

    ```shell title="Administrator workstation"
    ssh management@bifroest.example.org 'recording ls workload --limit=20'
    ```

    Supply the appropriate OpenSSH identity or agent for this separate connection. Direct SSH executes a management command and does not open a host shell.

### Disconnect or dispose of a workload session

Find the workload session with `session ls`, then choose **one** action:

* Close its current SSH and browser connections but keep the session reusable:

    ```shell
    bifroest @bifroest-admin session disconnect SESSION_UUID
    ```

* Revoke it, disconnect it and run its configured cleanup:

    ```shell
    bifroest @bifroest-admin session dispose SESSION_UUID
    ```

Disposal can remove containers, Pods or managed accounts and home directories, depending on the environment. For this unrestricted management login, neither command requires an additional permission. A command cannot target its own executing management session. See [`disconnect`](../reference/cli/session/disconnect.md) and [`dispose`](../reference/cli/session/dispose.md) for details and failure behavior.

## Browser alternative

Add the HTTPS settings from [Browser access](browser-access.md) and publish this administration flow with `discoverAsSlug: Admin` and `requirement.http.includedSlug: '^Admin$'`. Keep its existing requesting-name requirement. Open `/Admin`, choose **SSH key**, and sign in as `management` using its local private-key file. The browser provides metadata views and confirmed disconnect/dispose actions, not a configuration editor or a separate admin role. This example keeps artifact downloads disabled; [encrypted evidence](evidence.md) enables them separately.

The management tab starts at **Overview**. Its own side navigation is expanded
when the tab has enough space; on narrow tabs it opens over that tab's content.
The menu button expands or collapses it. Breadcrumbs remain visible, including
the selected session or Recording ID. Other connection tabs have independent
navigation and access. A single header control switches between a menu icon and
a back arrow. On narrow tabs the drawer overlays the content below the header;
the control remains accessible. Breadcrumbs always start with the non-clickable
**Bifröst** root. Session and Recording details include the flow and entry ID.
A second management tab requires a separate explicit sign-in; **Duplicate**
opens sign-in rather than sharing another tab's admitted channel.

**Sessions** loads its first page when opened. Use the Data Grid's **Filters**
button or a column menu to choose a field, operator and value. The quick search,
sorting and pagination also use the grid's native controls. Filters apply on the
server before pagination, not just to the visible page. The Community grid
supports one column filter at a time, in addition to quick search. Then open a
session's details by clicking a row or the magnifier in its last **Actions**
column. **Disconnect connections**
keeps the session reusable; **End session** revokes it and runs cleanup. Both
require confirmation of the exact target. A denied list does not grant or remove
other permissions; action-only access can use the grid's **Open by ID** pin to
enter a flow and session ID and prepare the action without a list read.

**Overview** shows configured flows. **Version** automatically loads the allowed
server version/build information and displays it as structured fields and feature
groups. Known features link to the documentation for that exact release; builds
without a release version use the unversioned public documentation. Unknown
features remain text. A short-version-only grant still cannot obtain long build
metadata.

The grids have native refresh controls, disabled during a read, and retain the
same grid while its custom loading overlay displays the phase, counts and progress
bar. Outside audit events, the eye switches between core fields and available
details; this presentation preference is saved for the origin. It does not grant
access to withheld fields, credentials or decrypted content.
Returning to an otherwise unchanged loaded view does not repeat its reads.

The normal pages are operational admin overviews, not automatically started
archive verification. Recording lists use an index of authenticated metadata
(signed header, seal and clear setup context), without verifying intervening
recording contents. Only the selected page, at most 20 recordings, is fully
checked before display. Stable metadata is reused across page changes where
native change stamps support that optimization. Windows currently rereads only
metadata on each query: its file change times can remain equal across completed
writes, so they must not authorize index reuse. This does not enable whole-source
content verification. A cold
index or broader search may inspect metadata throughout the selected source.
Progress distinguishes **Reading catalog metadata**, **Searching catalog
metadata**, and verification of the selected page. There is no four-second
overall deadline or manual continuation/cache-expiry window.

The toolbar's certificate (`license`) action opens **Verification options**.
Only **Start verification** starts the job. Its scope is the entire selected
source; the current page and filters do not narrow it. Recording full
verification reads all contents afresh, not a stamp-only cache. Its result is a
server report, not independent browser evidence; encrypted recordings can have
their envelopes checked without claiming private-content verification. The normal
list remains usable while this runs. Per-artifact limits still apply; use the
[CLI](../reference/cli/verification.md) for larger or independent forensic checks.

While verification runs, the initiating toolbar action becomes a `cancel` icon.
The custom overlay stays inside that DataGrid and shows the actual work phase and
counts; unknown totals use an indeterminate bar. Retained rows, filters and paging
remain usable. There is no separate page-level spinner or cancellation block.

Opening an auditlog normally loads a small, server-reported event page, **not** a
download or complete verification of the journal. The overview is explicitly
labelled as such. Its **Include private details** eye is an explicit opt-in for
this actor/source, shared by the grid and verification dialog. It includes private
fields in clear server reads and in locally checked audit exports, without a
second checkbox. A saved origin-wide display preference never activates this
opt-in. Encrypted private fields stay unavailable to the server; the same eye can
include them after explicit local decryption, never upload a key or treat unknown
fields as absent flow assignments. Changing the eye in a locally checked view
reprojects the already downloaded bytes locally, preserving filters and paging.

The audit verification dialog contains the depth, journal scope, signing-ID and
local-key options. When bytes are already available, it explicitly distinguishes
downloading a fresh source snapshot from checking the downloaded snapshot again.
Only a completed local verification and bounded event index may publish a new
local grid. Its toolbar action then becomes `123`, **Direct data from the server**:
that action returns to the operational view, not a new verification. Provenance
and signer trust remain visible; there are no separate Overview/Local verification
buttons or options disclosure below the grid.

Audit downloads show transfer progress, followed by local integrity/private-event
verification and local indexing/filtering progress. Decryption keys remain local;
progress never establishes producer trust. These operations have no aggregate
execution deadline, but transport startup/liveness, native session lifetimes,
authorization, quotas and individual resource limits still apply. Aborting ends
the owned operation without logout or explicit server workload disposal. Leaving
its page or losing access also cancels unfinished work. No operation is retried
or reauthenticated automatically.

Counts are provisional status, not a partial result or successful completion.
The grid stays loading until its complete, policy-projected page is ready. Only
the explicitly selected local audit view claims completed local verification.
Failed or cancelled page reads discard provisional rows/cursors. A separate full
check leaves the prior overview available and never adopts an incomplete new
verification result. Server logs retain the actual failure and, for WebSocket operations,
its correlated request ID without exposing private causes in the browser.

**Recordings** and **Audit logs** are separate navigation entries and keep their
own selections and results. Opening a Recording prepares local playback after
verification; opening an audit log shows the operational event overview, not an
inventory of raw files. Explicit local verification on both pages uses the same
tab-local decryption-key cache described in
[HTTP security and limits](../reference/connection/http/security.md#management-and-evidence).
The grid's pin opens a popover for an exact ID; it does not replace filters or
issue a transfer until **Go** is selected. The audit-log pin requires **Auditlog
Name** and optionally accepts an **Event ID**; the verified event grid has its own
event-ID pin. Audit-event details open as an owned
page, not a modal. Server-reported and locally checked events use the same Details
layout, field labels, relationship links and Actions section. Opaque ID hints are
included in the breadcrumb without inventing a verified flow. Detail boxes have
no standalone X: breadcrumb parents return to the retained list. Tab and dialog
closing remain separate. The monitor and
checklist icons identify Recordings and Audit logs in navigation and Overview
actions. The left-panel-close icon only collapses navigation; it is not Back.

Session tables start with the session ID. Row actions and detail Actions provide
**Show recordings** and **Show audit logs**, selecting that flow and session in
the configured source. Recordings show a known session ID as a detail link and
offer **Show session** in both action locations. Events do the same for permitted
session and recording references, including **Show recording**. Table actions use
the matching navigation icons; detail actions add text. Missing, withheld or
unroutable context never creates a guessed relationship or a hidden-field action.
These links only navigate: target reads keep their live authorization checks and
do not automatically start a full verification or search other archives.

### Direct management links

After signing in through `/Admin` to the management flow `administration`, its
Overview is `/Admin/administration`. Without a Slug it is `/administration`.
These prefixes use the **management access flow name**, not its display title.
Append the following paths to that prefix:

| View | Path |
| --- | --- |
| Sessions | `/sessions`, `/sessions/<flow>`, `/sessions/<flow>/<sessionId>` |
| Recordings | `/recordings`, `/recordings/<flow>`, `/recordings/<flow>/<recordingId>` |
| Audit logs/events | `/auditlogs`, `/auditlogs/<auditlog>`, `/auditlogs/<auditlog>/<flow>`, `/auditlogs/<auditlog>/<flow>/<eventId>` |
| Version | `/version` |

Recording links may include `?auditlog=workload` to select their source explicitly;
no global search through unrelated archives is required. If a Recording's flow
is not yet known, the pin retains `?recording=<recordingId>&auditlog=workload`
until local verification can replace it with the canonical flow path. An audit
event shortcut similarly uses `/auditlogs/<auditlog>?event=<eventId>` until the
verified event identifies its flow. In audit-event paths, `-` means **no flow
assigned**, never “flow still unknown”.

Recording and audit-event links may also include `sessionId=<sessionId>` (for
example `/recordings/worker?auditlog=workload&sessionId=<sessionId>`). Flow and
session selection apply to the entire server-side dataset and are bound into its
cursor; the session predicate is visibly preselected in the native Community
filter. Changing an exact session predicate to a non-exact one removes that exact
URI selection. A redacted local export cannot establish a missing flow/session
assignment; enable its eye explicitly when that private context is needed.

An exact Flow filter binds both the URI and the queried dataset to that literal,
case-sensitive flow. Changing to a non-exact operator removes the flow segment.
Overview's auditlog links and last-column actions navigate to the corresponding
audit log, sessions, Recordings or flow-scoped events. Back/Forward and reload
preserve the requested context. Reload still requires explicit sign-in or **Use
saved access**, and the authorized management flow must match the link; URLs
never restore grants or terminal executions. The server delivers the static SPA
entry for these links; all React rendering happens in the browser.

Returning through a flow breadcrumb to an already loaded source/flow dataset
retains its list rather than querying it again. Making a sole, automatically
selected auditlog explicit in a detail URL does not change that dataset. A new
flow or source still requires its own authorized read; rows from an earlier
successful read are never displayed as the result of a failed new read.

Management tab labels follow their selected main page. Live shell tab labels
start with the resolved flow title (`title`, or `name`) and follow the shell's
terminal title when a nonempty one is supplied, with the login identity
still available in the tooltip. These titles are untrusted display text and do
not alter the browser page title or another tab. Recorded terminal titles do not
rename tabs.

Like a terminal, each management tab owns one admitted connection. Its
**Connection settings** use the flow's keepalive policy and saved preference;
enforced intervals cannot be changed. A channel admitted before the ten-minute
web-access deadline can continue serving authorized management operations after
that deadline. Keepalive does not renew the web credential, session timeout or
RememberMe lifetime. Each operation still checks current authorization and uses
the normal audit/Recording and confirmation paths. Opening a management channel
does not start a shell or workload process.

After a disconnect or denied access, choose **Sign in again**. There is no
automatic reconnect or authentication. The new access view does not discard
locally loaded recording data from the old view.

## Next steps

* [Verify encrypted evidence on a workstation](evidence.md) enables controlled artifact transfer and keeps decryption local.
* [Remote-access reference](../reference/cli/management.md) documents SSH agents, custom settings and permissions.
* [Management environment properties](../reference/environment/management.md) describe the server-side access controls.
