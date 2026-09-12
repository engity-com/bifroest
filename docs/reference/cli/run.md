---
description: Start the Bifröst server.
---

# `bifroest run` {: #run }

Starts Bifröst with the selected [configuration](../configuration.md) and runs until the process receives a termination signal. On Windows, the same command also acts as the service entry point when launched by the Service Control Manager.

## Syntax

`bifroest run [flags]`

## Flags {: #run-flags }

Includes [all general flags](index.md#general-flags).

<<flag("configuration", ref("File Path", "../data-type.md#file-path", ref("Configuration", "../configuration.md")), default="<os specific>", aliases=["c"], id_prefix="run-", heading=3)>>
Configuration file to load.

The default depends on the platform:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="run-", heading=3)>>
Windows only. Name used when `run` is launched by the Windows Service Control Manager.

## Example

See [Configuration](../configuration.md) for a minimal configuration and startup example.
