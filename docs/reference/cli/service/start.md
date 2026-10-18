---
description: Start the Bifröst Windows service or macOS LaunchDaemon.
---

# `bifroest service start`

Starts an installed Bifröst service.

## Syntax

<<cli_syntax("service start")>>

## Arguments

None.

## Flags {: #service-start-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-start-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS.

## Output

Requests service startup. A service-manager error is logged to stderr and returns a nonzero exit status.

## Examples

### Start after an installation without immediate startup

1. Install with [`service install --start=false`](install.md#examples).
2. Start locally in an elevated terminal:

    ```powershell title="Windows"
    bifroest service start
    ```

    ```shell title="macOS"
    sudo bifroest service start
    ```

## Availability

<<cli_availability(linux=False)>>

The service must already be installed. Requires Administrator privileges on Windows and root privileges on macOS.
