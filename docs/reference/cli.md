---
description: How to operate with Bifröst via its Command Line Interface (CLI). What commands are available?
---

# Command line interface (CLI)

Bifröst is usually available via its `bifroest` command on each operating system.

## Running the server {. #run}

Syntax: `bifroest run [flags]`

### Flags {. #run-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", ref("File Path", "data-type.md#file-path", ref("Configuration", "configuration.md")), default="<os specific>", aliases=["c"],id_prefix="run-", heading=4)>>

The default value varies depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

## Show version {. #version}

Syntax: `bifroest verion [flags]`

### Flags {. #version-flags}

Includes [all general flags](#general-flags).

## General

### Flags {. #general-flags}

<<flag("log.level", "Log Level", "data-type.md#log-level", default="INFO", heading=4)>>
Defines the minimum level at which the log messages will be logged.

<<flag("log.format", "Log Format", "data-type.md#log-format", default="text", heading=4)>>
In which format the log output should be printed.

<<flag("log.colorMode", "Log Color Mode", "data-type.md#log-color-mode", default="auto", heading=4)>>
Tells whether to log in color or not.

<<flag("version", default="auto", heading=4)>>
Same as using sub-command [`version`](#version).
