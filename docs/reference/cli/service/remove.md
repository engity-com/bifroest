---
description: Remove the Bifröst Windows service.
---

# `bifroest service remove`

Removes an installed Bifröst service from the Windows Service Control Manager.

## Syntax

`bifroest service remove [flags]`

## Flags {: #service-remove-flags }

Includes [all general flags](../index.md#general-flags).

<<flag("serviceName", "string", default="engity-bifroest", id_prefix="service-remove-", heading=3)>>
Name of the service.

<<flag("stop", "bool", default=True, id_prefix="service-remove-", heading=3)>>
Stops the service before removing it. Use `--no-stop` to remove it without first stopping it. The default behavior is equivalent to first calling [`bifroest service stop`](stop.md).
