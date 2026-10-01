---
description: Manage Bifröst as a Windows service or macOS LaunchDaemon.
---

# `bifroest service` {: #service }

Service commands install and control Bifröst through the Windows Service Control Manager or macOS `launchd`.

!!! note
     These commands are available on Windows and macOS. Service management requires an elevated Administrator terminal on Windows and `root` privileges on macOS.

## Commands

* [`bifroest service install`](install.md) installs the service and optionally starts it.
* [`bifroest service remove`](remove.md) optionally stops and removes the service.
* [`bifroest service start`](start.md) starts the installed service.
* [`bifroest service stop`](stop.md) stops the installed service.
