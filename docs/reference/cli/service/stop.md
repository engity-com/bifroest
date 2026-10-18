---
description: Stop the Bifröst Windows service or macOS LaunchDaemon.
---

# `bifroest service stop`

Stops an installed Bifröst service if it is running.

## Syntax

<<cli_syntax("service stop")>>

## Arguments

None.

## Flags {: #service-stop-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-stop-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS.

## Output

Requests service shutdown through the platform service manager. A service-manager error is logged to stderr and returns a nonzero exit status.

## Examples

### Stop the installed service

Run locally in an elevated terminal:

```powershell title="Windows"
bifroest service stop
```

```shell title="macOS"
sudo bifroest service stop
```

Use [`service start`](start.md) to start it again, or [`service remove`](remove.md) to remove its registration.

## Availability

<<cli_availability(linux=False)>>

Requires Administrator privileges on Windows and root privileges on macOS.
