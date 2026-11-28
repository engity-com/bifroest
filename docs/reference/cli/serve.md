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

<<flag("watch", "off | preserve | reconnect | reuse", default="off", id_prefix="run-", heading=3)>>
Watches the selected configuration file. A bare `--watch` means `--watch=preserve`; without the flag, watching stays off. `false`, `no` and `0` are aliases for `off`; `true` means `preserve`.

`preserve` retains existing connections on their admitted configuration. `reconnect` closes connections of flows with relevant changes. `reuse` preserves connections and additionally permits more existing sessions to be reused after fresh authentication and target/credential checks. Known presentation-only changes do not invalidate browser grants or force reconnection in any mode. Invalid or unsupported candidates are rejected as a whole. See the [mode definitions, supported scope and monitoring](../../setup/operations.md#reload-configuration-without-restarting).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="run-", heading=3)>>
Windows only. Name registered with SCM; supplied by [`service install`](service/install.md).

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

### Opt into live reload

```shell
bifroest serve --configuration configuration.yaml --watch
```

The flag also works with `run` and can be persisted through [`service install`](service/install.md#service-install-flag-watch). It is an invocation option, not a Bifröst YAML property.

## Availability

<<cli_availability()>>

For installation and control through the platform service manager, see [`service`](service/index.md).
