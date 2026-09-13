---
description: Operate Bifröst through its command-line interface.
---

# Command line interface (CLI)

Bifröst is available through the `bifroest` executable. Commands perform server operation, key management, audit-journal processing, and platform-specific service management.

## Commands

* [`bifroest run`](run.md) starts the Bifröst server.
* [`bifroest version`](version.md) prints version and build information.
* [`bifroest key`](key/index.md) groups commands for generating and exchanging SSH trust material.
* [`bifroest audit`](audit/index.md) groups commands for verifying and exporting audit journals.
* [`bifroest service`](service/index.md) manages the Bifröst Windows service.
* [`bifroest help`](help.md) shows help for the CLI or a selected command.

## General flags {: #general-flags }

General flags are available with every command.

<<flag("help", "bool", default=False, heading=3)>>
Shows context-sensitive help. Use [`bifroest help`](help.md) to request help for a specific command path.

<<flag("log.level", "Log Level", "../data-type.md#log-level", default="INFO", heading=3)>>
Defines the minimum level at which log messages are emitted.

<<flag("log.format", "Log Format", "../data-type.md#log-format", default="text", heading=3)>>
Controls the format of log output.

<<flag("log.colorMode", "Log Color Mode", "../data-type.md#log-color-mode", default="auto", heading=3)>>
Controls whether text log output uses colors.

<<flag("version", "bool", default=False, heading=3)>>
Prints version details. For command-specific output control, use [`bifroest version`](version.md).
