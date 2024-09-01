---
description: Documentation how Bifröst can be configured will all its possible properties.
---
# Configuration

Bifröst will be configured in the [YAML language](https://en.wikipedia.org/wiki/YAML).

It can be either is taken by default from:

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
Defines how the sessions inside Bifröst are handled, where and how.

<<property("flows", "Flow", "flow.md", required=True)>>
Defines which flows are evaluated for user sessions.

<<property("housekeeping", "Housekeeping", "housekeeping.md")>>
Defines how Bifröst will clean up it's sessions and connections.

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
    ```

2. ??? plain "Drop in replacement for OpenSSH sshd"
    ```yaml title="<< asset_link('contrib/configurations/sshd-dropin-replacement.yaml') >>"
    --8<-- "contrib/configurations/sshd-dropin-replacement.yaml"
    ```

3. ??? plain "Complex"
    ```yaml title="<< asset_link('contrib/configurations/demo.yaml') >>"
    --8<-- "contrib/configurations/demo.yaml"
    ```


