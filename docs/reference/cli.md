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

## Service management {. #service}

!!! note
     Only available on Windows.

### Installation {. #service-install}

Installation of Bifröst as service inside the operating system, which will let it run upon system start and with full privileges.

Syntax: `bifroest service install [flags]`

#### Flags {. #service-install-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-install-", heading=5)>>
Name of the service.

<<flag("configuration", ref("File Path", "data-type.md#file-path", ref("Configuration", "configuration.md")), default="C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml", aliases=["c"], id_prefix="service-install-", heading=5)>>
Configuration location to use for the installed service.

<<flag("start", "bool", default=True, id_prefix="service-install-", heading=5)>>
If installed, should it be started immediately. This calls implicitly [`bifroest service start`](#service-start).

### Removal {. #service-remove}

Will remove an installed service instance of Bifröst from the operating system.

Syntax: `bifroest service remove [flags]`

#### Flags {. #service-remove-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-remove-", heading=5)>>
Name of the service.

<<flag("stop", "bool", default=True, id_prefix="service-remove-", heading=5)>>
Same as calling [`bifroest service stop`](#service-stop) before this command.

### Start {. #service-start}

Will start the installed service instance of Bifröst.

Syntax: `bifroest service start [flags]`

#### Flags {. #service-start-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-start-", heading=5)>>
Name of the service.

### Stop {. #service-stop}

Will stop the installed service instance of Bifröst (if running).

Syntax: `bifroest service stop [flags]`

#### Flags {. #service-stop-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-stop-", heading=5)>>
Name of the service.

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
