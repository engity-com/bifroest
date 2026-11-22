---
description: Configure authorized SSH and browser access to Bifröst management operations.
toc_depth: 5
---

# Management environment

The management environment provides administrative commands over SSH and a structured browser view: inspect server state, disconnect sessions and dispose of sessions. Unlike the [local environment](local.md), it does not provide a host shell. PTYs, SFTP, agent forwarding and port forwarding are not available.

Use a dedicated, explicitly authorized [flow](../flow.md), with management and workload logins matched separately. There is no implicit administrator role. Management connections create regular sessions and follow the flow's audit-logging configuration.

To keep management SSH-only when an HTTPS endpoint is enabled, set `http.enabled: false` on its flow.

!!! warning "Default management access includes session control"
    The default permissions allow [disconnecting](../cli/session/disconnect.md) and [disposing](../cli/session/dispose.md) sessions in any flow. Disposal can remove containers, Pods or managed accounts and home directories. Use an explicit `access` object for read-only or restricted access.

See [Remote access](../cli/management.md) for SSH commands and client settings, or [Browser access](../../guides/browser-access.md) for the browser view. Forced-command credentials do not grant unrestricted management access.

## Configuration {: #configuration}

The common `environment.variables` option is not supported by this environment.

<<property("type", "Environment Type", default="management", required=True)>>
Must be `management`.

<<property("access", "bool, template or object", template_context="../context/authorization.md")>>
Controls management operations across SSH, the integrated client and the browser. Every level accepts a Boolean, a template or an object containing the known children below. A scalar applies to all descendants.

If `access` is omitted, the default object grants the rights shown in the table. An **explicit object inherits no defaults**: every omitted child is recursively `false`. Thus `access: {}` denies all operations, while `access: true` grants every right, including credentials and original evidence.

| Right | Default | Allows |
| --- | --- | --- |
| `version.read` | `true` | Version and build information |
| `metrics.read` | `true` | Management metrics |
| `flows.read` | `true` | Flow listings and redacted settings |
| `flows.credentials` | `false` | Unredacted `flow show` output, additionally requiring `flows.read` |
| `sessions.read` | `true` | Session listings and details |
| `sessions.disconnect` | `true` | Disconnecting current session connections |
| `sessions.dispose` | `true` | Revoking sessions and running cleanup |
| `auditlogs.read` | `true` | Auditlog metadata and redacted settings |
| `auditlogs.events` | `true` | Public audit events and server-side redacted export/merge |
| `auditlogs.verify` | `true` | Server-side audit verification |
| `auditlogs.download` | `false` | Original audit downloads and sensitive audit output |
| `recordings.read` | `true` | Recording metadata |
| `recordings.verify` | `true` | Server-side Recording verification |
| `recordings.download` | `false` | Original Recording downloads, export and playback |
| `keys.read` | `true` | Public SSH key exports |

Templates use the verified administrator's [authorization context](../context/authorization.md), not the selected target flow or session. They must render exactly `true` or `false`, ignoring surrounding whitespace. Invalid results and evaluation errors deny the operation. Unknown properties, duplicate keys, `null` and lists are configuration errors.

Rights are independent: session control does not grant session details, and download rights do not grant metadata listings. A browser-wide Recording download also requires `recordings.read` because it inventories the source. Sensitive audit event queries additionally require `auditlogs.events`. Forced commands further restrict permitted operations; they never expand `access`. Rights apply to operations across all target flows, not just the administrator's own sessions.

!!! warning "Credentials and originals can disclose secrets"
    `flows.credentials` can expose configured secrets; browser metadata and auditlog settings remain redacted. Original audit journals and Recordings can contain private content, even without encryption. Grant these rights only to trusted administrators. `--with-sensitive` is an explicit disclosure choice, not a permission. Client-side decryption keys remain on the client.

## Examples {: #examples}

1. Management access, including session control, with credential disclosure and artifact downloads disabled:
    ```yaml
    type: management
    ```
2. Metrics-only access:
    ```yaml
    type: management
    access:
      metrics: true
    ```
3. Read sessions and conditionally disconnect them, without disposal or other operations:
    ```yaml
    type: management
    access:
      sessions:
        read: true
        disconnect: '{{ eq .authorization.entry.name "operator" }}'
    ```

For a complete configuration with separate workload and management flows, authentication and audit logging, follow [Manage a Bifröst host remotely](../../guides/management.md). The [encrypted-evidence guide](../../guides/evidence.md) covers artifact downloads and local decryption.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
