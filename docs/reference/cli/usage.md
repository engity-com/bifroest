---
description: Understand Bifröst command syntax, configuration, execution modes and file inputs.
---

# Invocation and data sources

The general command form is:

<<cli_syntax("", "[@target] <command> [<subcommand>...] [flags] [arguments]", flags_link="#general-flags", argument_links={"command": "index.md#find-a-command", "subcommand": "#syntax-notation", "arguments": "#syntax-notation"})>>

A remote target, when present, must be the **first argument**. The command's reference page lists its accepted arguments and flags. Use `--flag=false` to disable a boolean option whose default is true, for example `bifroest service install --start=false`.

Uppercase tokens in examples, such as `PRODUCER_ID`, `SESSION_UUID` and `RECORDING_UUID`, are placeholders to replace with values from the preceding steps.

## Syntax notation

Command and subcommand names are literal words, for example `recording show` or `key export host`. Angle brackets identify an argument to supply, square brackets mark optional parts, and `...` means that values can be repeated. Select an argument in a command's syntax to jump to its description; `flags` links to that command's options.

## Execution modes

| Mode | Example | Configuration and state |
| --- | --- | --- |
| Local CLI | `bifroest session ls` | Runs on the CLI machine and reads local configuration, state or file inputs. |
| Integrated remote client | `bifroest @bifroest-admin session ls` | Connects to the server's authorized management flow and reads server state. |
| Direct SSH | `ssh management@bifroest.example.org 'session ls'` | Runs inside the server's management flow using its loaded configuration. |

Availability is specified on each executable command's page. Server startup, service installation and key bootstrap commands run locally. The [remote-access reference](management.md) explains SSH configuration and management permissions.

## Availability tables

Executable command pages show platform support in the same `generic`/`extended` notation as the [binary distributions](../../setup/distribution.md#os). A check means supported, a cross means unsupported, and an empty circle means that the edition is not distributed for that platform.

The invocation table separately shows whether the command supports the local CLI, the integrated `@target` client and direct SSH. Platform support refers to the machine running that command. For example, the local `service` commands are available in the macOS and Windows binaries, with no Linux support or remote invocation.

## Configuration

Commands that select configured local state accept `--configuration PATH` (alias `-c`) where documented. Without it, they load the platform default:

| Platform | Default configuration |
| --- | --- |
| Linux | `/etc/engity/bifroest/configuration.yaml` |
| macOS | `/Library/Application Support/Engity/Bifroest/configuration.yaml` |
| Windows | `C:\ProgramData\Engity\Bifroest\configuration.yaml` |

The local CLI needs filesystem permission to read the selected configuration, state and relevant keys. Local `session` inspection supports filesystem repositories. Through management, the service reads its active session repository.

`--configuration` cannot be combined with `@target`. Direct SSH commands use the running service's configuration and do not accept a replacement configuration file.

## Repositories and copied evidence

The execution mode and the input source are separate choices:

* An **auditlog name** selects a repository from configuration, for example `bifroest audit verify default`.
* An audit **`--source` directory** selects a complete copied journal, including its signed head and all required segments.
* A Recording **file argument** selects a copied `.bcast`, `.becast` or signed `.cast` file, where supported.

Offline file inputs need an independently trusted producer ID; they do not need the server's signing private key or a local server configuration. They are local to the CLI machine and cannot be combined with `@target`. Remote commands select an auditlog name and, for Recordings, a Recording ID.

For downloaded evidence, output files and decryption-key paths belong to the **CLI machine**. Remote metadata is queried on the server; remote artifact verification, export and playback download signed originals and verify them on the client. See [Trust and verification](verification.md).

## General flags {: #general-flags }

These flags configure the executable in local and `@target` mode. Direct management SSH uses the server's logging configuration and does not expose the executable's logging flags; `--help` remains available.

<<flag("help", "bool", default=False, aliases=["h"], heading=3)>>
Shows help without executing the selected command. See [Help](help.md).

<<flag("log.level", "Log Level", "../data-type.md#log-level", default="INFO", heading=3)>>
Minimum level for log messages.

<<flag("log.format", "Log Format", "../data-type.md#log-format", default="text", heading=3)>>
Format of log messages; independent of a command's result format.

<<flag("log.colorMode", "Log Color Mode", "../data-type.md#log-color-mode", default="auto", heading=3)>>
Color mode for logs: `auto`, `always` or `never`.

## Examples

### Inspect a non-default local configuration

1. Prepare a valid [Bifröst configuration](../configuration.md) at `/etc/engity/bifroest/staging.yaml`.
2. Inspect the flows selected by that file:

    ```shell
    bifroest flow ls --configuration /etc/engity/bifroest/staging.yaml
    ```

3. Inspect the available options for a different execution mode:

    ```shell
    bifroest @bifroest-admin flow ls --help
    ```

    This prints client-side help without opening an SSH connection.
