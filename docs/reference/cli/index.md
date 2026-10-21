---
description: Find Bifröst commands, their arguments, and local or remote usage.
---

# Command line interface (CLI)

Use `bifroest` to run the server, inspect its state, manage SSH keys, and work with signed audit journals and session recordings.

## Find a command

| Command | Purpose |
| --- | --- |
| [`serve`](serve.md) | Run the Bifröst server. |
| [`flow`](flow/index.md) | List configured flows and inspect their settings. |
| [`session`](session/index.md) | Inspect sessions; remotely disconnect or dispose of them. |
| [`audit`](audit/index.md) | Inspect audit logs and events; verify, export or merge journals. |
| [`recording`](recording/index.md) | Find, inspect, verify, export and play session recordings. |
| [`key`](key/index.md) | Generate keys and exchange SSH trust material. |
| [`service`](service/index.md) | Install and control the Windows service or macOS LaunchDaemon. |
| [`version`](version.md) | Show version and build information. |

Each executable command's reference documents its syntax, arguments, flags, output, examples and availability.

## Choose how to call it

* **On the Bifröst host:** `bifroest session ls` reads the configured local storage.
* **From an administrator's workstation:** `bifroest @bifroest-admin session ls` uses the integrated SSH client.
* **Through a standard SSH client:** `ssh management@bifroest.example.org 'session ls'` runs a command in the authorized management flow.
* **With copied evidence:** `bifroest recording verify --expectedProducerId PRODUCER_ID session.bcast` verifies a local artifact.

Read [Invocation and data sources](usage.md) for configuration paths and the difference between an execution mode and a file input. [Remote access](management.md) documents SSH targets, authentication and client settings.

## General flags {: #general-flags }

The executable's general flags are:

* [`--help`](usage.md#flag-help){: #flag-help }
* [`--log.level`](usage.md#flag-log.level){: #flag-log.level }
* [`--log.format`](usage.md#flag-log.format){: #flag-log.format }
* [`--log.colorMode`](usage.md#flag-log.colorMode){: #flag-log.colorMode }

Command-specific flags such as `--format`, `--configuration` and `--output` are documented on the commands that accept them. Direct SSH uses the server's log settings.

For more background, see [Output and errors](output.md) and [Trust and verification](verification.md).

## Examples

For a complete setup followed by actual commands, choose an end-to-end guide:

* [Manage a Bifröst host remotely](../../guides/management.md).
* [Record, find and replay a session](../../guides/recording.md).
* [Verify encrypted evidence on a workstation](../../guides/evidence.md).

For help with an installed version, use `bifroest --help` or `bifroest recording play --help`.
