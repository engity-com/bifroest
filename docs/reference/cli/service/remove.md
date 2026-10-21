---
description: Remove the Bifröst Windows service or macOS LaunchDaemon.
---

# `bifroest service remove`

Removes an installed Bifröst service from the Windows Service Control Manager or macOS `launchd`. On macOS, configuration, state, keys, recordings and logs are preserved.

## Syntax

<<cli_syntax("service remove")>>

## Arguments

None.

## Flags {: #service-remove-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-remove-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS.

<<flag("stop", "bool", default=True, id_prefix="service-remove-", heading=3)>>
Stops the service before removing it on Windows. Use `--stop=false` to remove it without first stopping it. This flag is not available on macOS, where removing a LaunchDaemon always stops and unregisters it first.

## Output

Removes the service registration. On macOS, configuration, state, keys, Recordings and logs are preserved. Errors are logged to stderr and return a nonzero exit status.

## Examples

### Remove an installed service

1. Select the host where the service was installed and open an elevated terminal.
2. On Windows, run:

    ```powershell
    bifroest service remove
    ```

    On macOS, run:

    ```shell
    sudo bifroest service remove
    ```

## Availability

<<cli_availability(linux=False)>>

Requires Administrator privileges on Windows and root privileges on macOS.
