---
description: Manage Bifröst as a Windows service or macOS LaunchDaemon.
---

# `bifroest service` {: #service }

Service commands install and control Bifröst through the Windows Service Control Manager or macOS `launchd`.

## Commands

| Command | Purpose |
| --- | --- |
| [`install`](install.md) | Install the platform service and optionally start it. |
| [`remove`](remove.md) | Remove its registration; macOS always stops it first. |
| [`start`](start.md) | Start an installed service. |
| [`stop`](stop.md) | Stop the service through the platform manager. |

For direct foreground startup, see [`serve`](../serve.md).

## Examples

Follow [host installation](../../../setup/on-host.md) for platform configuration and privileges, then use the numbered [installation examples](install.md#examples).
