---
description: Documentation how Bifröst can be configured will all its possible properties.
---
# Configuration

Bifröst will be configured in the [YAML language](https://en.wikipedia.org/wiki/YAML).

By default, the configuration is taken from the following location:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

This location can be changed by the `--configuration=<path>` flag when executing:
```{.shell linenums=0}
bifroest run --configuration=/my/config.yaml
```

## Properties

<<property("ssh", "SSH", "connection/ssh.md")>>
Defines how the SSH connections itself will behave.

<<property("session", "Session", "session/index.md")>>
Defines where and how the sessions inside Bifröst are handled.

<<property("flows", "Flow", "flow.md", required=True)>>
Defines which flows are evaluated for user sessions.

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

2. ??? plain "Drop in replacement for OpenSSH sshd"
    ```yaml
    --8<-- "contrib/configurations/sshd-dropin-replacement.yaml"
    ```

3. ??? plain "Docker environment with OpenID Connect authorization"
    This example is using the [Docker environment](environment/docker.md) with [OpenID Connection authorization](authorization/oidc.md).
    ```yaml
    flows:
      - name: docker
        authorization:
          type: oidcDeviceAuth
          issuer: https://login.microsoftonline.com/my-great-tenant-uuid/v2.0
          clientId: my-great-client-uuid
          clientSecret: very-secret-secret
          scopes:
            - openid
            - email
            - profile
        environment:
          type: docker
          image: alpine
    ```
