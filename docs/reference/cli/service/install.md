---
description: Install Bifröst as a Windows service.
---

# `bifroest service install`

Installs Bifröst as an automatically started Windows service.

## Syntax

`bifroest service install [flags]`

## Flags {: #service-install-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-install-", heading=3)>>
Name of the service.

<<flag("configuration", ref("File Path", "../../data-type.md#file-path", ref("Configuration", "../../configuration.md")), default="C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml", aliases=["c"], id_prefix="service-install-", heading=3)>>
Configuration file used by the installed service.

<<flag("start", "bool", default=True, id_prefix="service-install-", heading=3)>>
Starts the service immediately after installation. Use `--no-start` to install it without starting it. The default behavior is equivalent to subsequently calling [`bifroest service start`](start.md).

## Example

```powershell
bifroest service install --configuration C:\ProgramData\Engity\Bifroest\configuration.yaml
```
