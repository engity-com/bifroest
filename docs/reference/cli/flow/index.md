---
description: List configured Bifröst flows and inspect their settings.
---

# `bifroest flow`

Inspect the flows in the selected local configuration or in a running management service. These commands read settings; [flow configuration](../../flow.md) defines authorization and the environment used by SSH connections.

## Commands

| Command | Purpose |
| --- | --- |
| [`ls`](ls.md) | List flow names, selected audit logs and authorization/environment types. |
| [`show`](show.md) | Show the settings of one named flow. |

Arbitrary configuration strings are redacted in detail output as documented on `show`.

## Examples

Follow [Manage a Bifröst host remotely](../../../guides/management.md) to configure an administration flow alongside a local-account flow and inspect both with these commands.
