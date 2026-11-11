---
description: Documentation how Bifröst can be configured will all its possible properties.
---
# Configuration

Bifröst will be configured in the [YAML language](https://en.wikipedia.org/wiki/YAML).

By default, the configuration is taken from the following location:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* macOS: `/Library/Application Support/Engity/Bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

This location can be changed by the `--configuration=<path>` flag when executing:
```{.shell linenums=0}
bifroest run --configuration=/my/config.yaml
```

## Properties

<<property("ssh", "SSH", "connection/ssh.md")>>
Defines how the SSH connections itself will behave.

<<property("http", "HTTP", "connection/http/index.md")>>
Configures optional HTTPS browser access. Disabled by default. A startup failure in any enabled SSH or HTTPS endpoint prevents the service from starting.

<<property("session", "Session", "session/index.md")>>
Defines where and how the sessions inside Bifröst are handled.

<<property("flows", array_ref("Flow", "flow.md"), required=True)>>
Defines which flows are evaluated for user sessions.

<<property("environments", ref("Map", None, ref("Environment", "environment/index.md")))>>
Reusable environments keyed by name. Each value is an inline object with `type`
and that environment's settings, not a reference or a wrapper. The map key names
the definition; do not add a definition-name field inside it.
Provider settings such as a local account's `name` or a Kubernetes Pod's `name`
retain their usual meaning; they do not rename the definition.

<<property("authorizations", ref("Map", None, ref("Authorization", "authorization/index.md")))>>
Reusable authorizations keyed by name. Each value is an inline object with `type`
and that authorization's settings, without a separate definition-name field.
A flow selects exactly one authorization, either inline or by name, not a list
or a chain of providers.

For both maps, a `default` entry is optional and never created automatically.
Omitting a flow's corresponding setting, or setting it to `null` or `''`, uses
that map's `default` if defined; otherwise the setting is required. Explicit
references to unknown names are configuration errors.

<<property("auditlogs", ref("Map", None, ref("Audit log", "auditlog/index.md")))>>
Audit logs keyed by name, with their settings directly in each value. A defined,
selected logger is active; there is no audit-log `enabled` setting. A flow with
an omitted, `null` or empty `auditlog` uses `auditlogs.default` if defined,
otherwise it has no audit logging or recording. No default logger is created
implicitly. Unknown explicit references are configuration errors.

<<property("housekeeping", "Housekeeping", "housekeeping.md")>>
Defines how Bifröst will clean up its sessions and connections.

<<property("alternatives", "Alternatives", "alternatives.md")>>
Defines how the imp (if needed) behaves to help to bridge context boundaries, for example to enable port-forwarding into an OCI container.

<<property("startMessage", "string", template_context="context/core.md", default="")>>
If defined this message will be displayed in the log files of Bifröst on startup.

## Examples

1. Simple:
    ```yaml
    ssh:
      addresses: [ ":22" ]
      # ...
    session:
      type: fs
      # ...
    flows:
      - name: local
        # ...
    housekeeping:
      # ...
    alternatives:
      # ...
    startMessage: ""
    ```

2. ??? plain "Local-account host configuration"
    ```yaml
    --8<-- "contrib/configurations/on-host.yaml"
    ```

3. ??? plain "Reusable Docker configuration with OpenID Connect authorization"
    This example is using the [Docker environment](environment/docker.md) with [OpenID Connection authorization](authorization/oidc.md).
    ```yaml
    environments:
      docker:
        type: docker
        image: alpine
    authorizations:
      default:
        type: oidcDeviceAuth
        issuer: https://login.microsoftonline.com/my-great-tenant-uuid/v2.0
        clientId: my-great-client-uuid
        clientSecret: very-secret-secret
        scopes:
          - openid
          - email
          - profile
          - offline_access
    flows:
      - name: docker
        environment: docker
        # authorization is omitted: uses authorizations.default
        discoverAsSlug: docker
        requirement:
          http:
            includedSlug: '^docker$'
    ```
    Configure the [HTTP endpoint](connection/http/index.md) separately to publish
    `/docker`. Without an `auditlogs.default` entry or an explicit flow selection,
    this example does not log audit events or record sessions.

    To also accept `/bla-bla` as an alias, use
    `includedSlug: '^(docker|bla-bla)$'` while keeping `discoverAsSlug: docker`.
    A tab opened through `/bla-bla` keeps that URL scope when selected; it is not
    rewritten to `/docker`.
