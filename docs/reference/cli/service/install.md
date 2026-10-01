---
description: Install Bifröst as a Windows service or macOS LaunchDaemon.
---

# `bifroest service install`

Installs Bifröst as an automatically started Windows service or macOS LaunchDaemon. On macOS, Bifröst copies its current executable to `/Library/PrivilegedHelperTools/com.engity.bifroest` and creates `/Library/LaunchDaemons/com.engity.bifroest.plist` directly from the CLI.

## Syntax

`bifroest service install [flags]`

## Flags {: #service-install-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-install-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS, where the fixed LaunchDaemon label is `com.engity.bifroest`.

<<flag("configuration", ref("File Path", "../../data-type.md#file-path", ref("Configuration", "../../configuration.md")), default="C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml", aliases=["c"], id_prefix="service-install-", heading=3)>>
Configuration file used by the installed service. On macOS, the file must be below `/Library/Application Support/Engity/Bifroest`, owned by `root:wheel`, have no ACL and use permissions no broader than `0640`. The macOS default is `/Library/Application Support/Engity/Bifroest/configuration.yaml`.

<<flag("start", "bool", default=True, id_prefix="service-install-", heading=3)>>
Starts the service immediately after installation. Use `--no-start` to install it without starting it. The default behavior is equivalent to subsequently calling [`bifroest service start`](start.md).

## Example

```powershell
bifroest service install --configuration C:\ProgramData\Engity\Bifroest\configuration.yaml
```

```shell
sudo ./bifroest service install
```
