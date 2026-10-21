---
description: Install Bifröst as a Windows service or macOS LaunchDaemon.
---

# `bifroest service install`

Installs Bifröst as an automatically started Windows service or macOS LaunchDaemon. On macOS, Bifröst copies its current executable to `/Library/PrivilegedHelperTools/com.engity.bifroest` and creates `/Library/LaunchDaemons/com.engity.bifroest.plist` directly from the CLI.

```shell
bifroest service install --start=false
```

## Syntax

<<cli_syntax("service install")>>

## Arguments

None.

## Flags {: #service-install-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-install-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS, where the fixed LaunchDaemon label is `com.engity.bifroest`.

<<flag("displayName", "string", default="Engity's Bifröst", id_prefix="service-install-", heading=3)>>
Display name in Windows service listings. Unavailable on macOS.

<<flag("configuration", ref("File Path", "../../data-type.md#file-path", ref("Configuration", "../../configuration.md")), default="<os specific>", aliases=["c"], id_prefix="service-install-", heading=3)>>
Configuration file used by the installed service. On macOS, the file must be below `/Library/Application Support/Engity/Bifroest`, owned by `root:wheel`, have no ACL and use permissions no broader than `0640`. The macOS default is `/Library/Application Support/Engity/Bifroest/configuration.yaml`.

The Windows default is `C:\ProgramData\Engity\Bifroest\configuration.yaml`.

<<flag("start", "bool", default=True, id_prefix="service-install-", heading=3)>>
Starts the service immediately after installation. Use `--start=false` to install it without starting it. The default behavior is equivalent to subsequently calling [`bifroest service start`](start.md).

## Output

Registers the platform service and, by default, starts it. Errors are logged to stderr and return a nonzero exit status. There is no structured `--format` output.

## Examples

### Install on Windows before starting

1. Prepare the Windows [host configuration](../../../setup/on-host.md#windows).
2. In an elevated PowerShell terminal, install without immediate startup:

    ```powershell
    bifroest service install --configuration "C:\ProgramData\Engity\Bifroest\configuration.yaml" --start=false
    ```

3. Start the installed service:

    ```powershell
    bifroest service start
    ```

### Install a macOS LaunchDaemon

1. Prepare the protected configuration described in [macOS host installation](../../../setup/on-host.md#macos).
2. Install and start the daemon:

    ```shell
    sudo ./bifroest service install
    ```

## Availability

<<cli_availability(linux=False)>>

Requires an elevated Administrator terminal on Windows and root privileges on macOS.
