---
description: Start the Bifröst server.
---

# `bifroest serve` {: #run }

Starts Bifröst with the selected [configuration](../configuration.md) and runs until the process receives a termination signal. On Windows, the command also acts as the service entry point when launched by the Service Control Manager.

```shell
bifroest serve
```

## Syntax

<<cli_syntax("serve", flag_prefix="run")>>

`run` is an alias of `serve`.

## Arguments

None.

## Flags {: #run-flags }

Includes [all general flags](index.md#general-flags).

<<flag("configuration", ref("File Path", "../data-type.md#file-path", ref("Configuration", "../configuration.md")), default="<os specific>", aliases=["c"], id_prefix="run-", heading=3)>>
Configuration file to load.

The default depends on the platform:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* macOS: `/Library/Application Support/Engity/Bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

<<flag("windowsService", "bool", default=False, id_prefix="run-", heading=3)>>
Windows only. Explicitly run as a registered Windows Service Control Manager
(SCM) service. Without this flag, Bifröst uses automatic service detection.
Use it in manually registered SCM commands, particularly in Windows containers
where automatic detection may be unreliable. It does not register a service,
change its account, grant logon rights or enable privileges.

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="run-", heading=3)>>
Windows only. Must match the service name registered with SCM.

The built-in [service installer](service/install.md) supplies both arguments.
Private state and key files must be owned by the actual service identity.

## Output

Logs are written to stderr. Startup failure returns a nonzero exit status. An interrupt requests shutdown.

## Examples

### Start a configured server

1. Prepare a valid [host configuration](../../setup/on-host.md), or the two-flow configuration from [the management guide](../../guides/management.md).
2. Run Bifröst as the intended service user with the required host permissions:

    ```shell
    bifroest serve --configuration /etc/engity/bifroest/configuration.yaml
    ```

    For an installed system service, use its service manager instead of starting a second process on the same address and repositories.

### Manually registered Windows service

Use these arguments in the registered SCM command, not as a foreground command.
Replace the name and configuration path with those of the registered service:

```text
bifroest serve --windowsService --serviceName=custom-bifroest --configuration="C:\ProgramData\Engity\Bifroest\configuration.yaml"
```

Use [`bifroest service install`](service/install.md) instead when possible.

## Availability

<<cli_availability()>>

For installation and control through the platform service manager, see [`service`](service/index.md).
