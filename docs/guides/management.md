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

The management tab starts at **Bifröst**. Its own side navigation is expanded
when the tab has enough space; on narrow tabs it opens over that tab's content.
The menu button expands or collapses it. Breadcrumbs remain visible, including
the selected session or Recording ID. Other connection tabs have independent
navigation and access.
A second management tab requires a separate explicit sign-in; **Duplicate**
opens sign-in rather than sharing another tab's admitted channel.

**Sessions** loads its first page when opened. Use the Data Grid's **Filters**
button or a column menu to choose a field, operator and value. The quick search,
sorting and pagination also use the grid's native controls. Filters apply on the
server before pagination, not just to the visible page. The Community grid
supports one column filter at a time, in addition to quick search. Then open a
session's details. **Disconnect connections**
keeps the session reusable; **End session** revokes it and runs cleanup. Both
require confirmation of the exact target. A denied list does not grant or remove
other permissions; action-only access can use **Advanced: target by ID**.

**Bifröst** loads the short version and configured flows. Detailed build
information is optional. Returning to a loaded view does not repeat its reads;
use the refresh controls for current data.

**Recordings** and **Audit logs** are separate navigation entries and keep their
own selections and results. Opening a Recording prepares local playback after
verification; opening an audit log shows verified events, not an inventory of
raw files. Both use the same tab-local decryption-key cache described in
[HTTP security and limits](../reference/connection/http/security.md#management-and-evidence).

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
