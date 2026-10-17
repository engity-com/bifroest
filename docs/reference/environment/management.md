---
description: Configure an authorized SSH flow for Bifröst management commands.
---

# Management environment

The `management` environment provides read-only administrative commands through a dedicated, explicitly authorized [flow](../flow.md). It does not launch a host shell, SFTP server, or port-forwarding destination. Select a distinct requesting SSH username so the management flow cannot accidentally match a normal login.

```yaml
auditlog:
  - name: administration
    enabled: true
    identityFile: /etc/engity/bifroest/administration-audit-key
    directory: /var/lib/engity/bifroest/administration-audit
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
      allowArtifactTransfer: true  # Only when client-side verification/download is needed.
```

Authentication and authorization use the configured flow as usual; there is no implicit administrator role. Bifröst still creates a session for the management connection. If audit logging is enabled, management SSH operations also pass through the existing audit lifecycle. Consult the [management CLI](../cli/management.md) for commands and client setup.

## Properties

<<property("type", "Environment Type", default="management", required=True)>>
Enables the built-in management-command environment for this flow.

<<property("includingCredentials", "bool", default=False)>>
Controls whether `flow show` exposes credentials **in that management flow's output**. The default is `false`: arbitrary configuration strings, commands, URLs, image references, credentials and environment variables are redacted as `***redacted***`. A syntactically valid image name can still contain private information and is therefore not public metadata. Structural names, booleans, numeric settings and fixed Docker/Kubernetes image-pull policies remain visible. Audit-log target settings are redacted independently. This option is intended only for temporary debugging or migration.

<<property("allowArtifactTransfer", "bool", default=False)>>
Permits the management flow to download original signed audit journals and sealed Recordings for **client-side** verification, export and playback. The default is `false`: listing, metadata inspection, public audit events and direct-SSH verification remain available, but binary artifact downloads and direct-SSH sensitive audit events or Recording content are denied. Set this only for flows whose administrators may access original evidence, including unencrypted private content. `--with-sensitive` still controls whether the normal CLI displays sensitive content; it is not a server-side authorization boundary.

!!! warning "Do not enable includingCredentials in production"
    `includingCredentials: true` can reveal secrets configured in other flows to every administrator authorized by this management flow. Bifröst emits a warning in the startup logs for each management flow with this option enabled. Limit access to the flow and turn the option off again after debugging or migration.

The management environment does not support the common `environment.variables` option. Neither SSH-agent forwarding nor a decryption private key is required on the server for management queries.
