---
description: Stop the Bifröst Windows service or macOS LaunchDaemon.
---

# `bifroest service stop`

Stops an installed Bifröst service if it is running.

## Syntax

`bifroest service stop [flags]`

## Flags {: #service-stop-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-stop-", heading=3)>>
Name of the service on Windows. This flag is not available on macOS.
