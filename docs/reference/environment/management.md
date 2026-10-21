---
description: Configure an authorized SSH flow for Bifröst management commands.
toc_depth: 5
---

# Management environment

The management environment provides read-only administrative commands over SSH. Unlike the [local environment](local.md), it does not provide a host shell. PTYs, SFTP, agent forwarding and port forwarding are not available.

Use a dedicated, explicitly authorized [flow](../flow.md), with management and workload logins matched separately. There is no implicit administrator role. Management connections create regular sessions and follow the flow's audit-logging configuration.

See [Remote access](../cli/management.md) for supported commands and client settings.

## Configuration {: #configuration}

The two permissions below are independent and disabled by default. The common `environment.variables` option is not supported by this environment.

<<property("type", "Environment Type", default="management", required=True)>>
Must be `management`.

<<property("includingCredentials", "bool", default=False)>>
Controls whether `flow show` displays unredacted configuration strings **in this management flow's output**.

By default, credentials and other arbitrary strings, including commands, URLs, image references and environment variables, are replaced with `***redacted***`. Even a valid image name can contain private information. Structural names, booleans, numeric settings and fixed Docker/Kubernetes image-pull policies remain visible. Audit-log target settings are redacted independently.

!!! warning "Do not enable includingCredentials in production"
    `includingCredentials: true` can reveal secrets configured in other flows to every administrator authorized by this management flow. Bifröst logs a startup warning for each flow with this option enabled. Use it only temporarily for debugging or migration, restrict access to the flow and turn it off afterwards.

<<property("allowArtifactTransfer", "bool", default=False)>>
Permits downloading original signed audit journals and sealed Recordings for **client-side** verification, export and playback. Private decryption keys stay on the client; the server does not need an SSH agent or a decryption key for management queries.

With the default `false`:

* Listing, metadata inspection, public audit events and direct-SSH verification remain available.
* Binary artifact downloads and direct-SSH access to sensitive audit events or Recording content are denied.

!!! warning "Original artifacts can contain sensitive data"
    Enable this only for flows whose administrators may access original evidence, including unencrypted private content. The client flag `--with-sensitive` controls what the CLI displays; it does not grant or restrict server-side permissions.

## Examples {: #examples}

1. Read-only metadata access with both permissions disabled:
    ```yaml
    type: management
    ```
2. Allow client-side evidence verification, export and playback while keeping configuration credentials redacted:
    ```yaml
    type: management
    allowArtifactTransfer: true
    ```

For a complete configuration with separate workload and management flows, authentication and audit logging, follow [Manage a Bifröst host remotely](../../guides/management.md). The [encrypted-evidence guide](../../guides/evidence.md) covers artifact downloads and local decryption.

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
