---
description: Remove the Bifröst Windows service or macOS LaunchDaemon.
---

# `bifroest service remove`

Removes an installed Bifröst service from the Windows Service Control Manager or macOS `launchd`. On macOS, configuration, state, keys, recordings and logs are preserved.

## Syntax

`bifroest service remove [flags]`

## Flags {: #service-remove-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-remove-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS.

<<flag("stop", "bool", default=True, id_prefix="service-remove-", heading=3)>>
Stops the service before removing it on Windows. Use `--no-stop` to remove it without first stopping it. This flag is not available on macOS, where removing a LaunchDaemon always stops and unregisters it first.
