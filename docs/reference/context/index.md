---
description: Context are used while evaluating templates in Bifröst.
---

# Context objects

Context objects depend on where they are used and are mainly injected into [template evaluation](../templating/index.md). For local account-management templates, see [Context Local Environment](local-environment.md).

## Current connection

Where a current incoming connection exists, `.connection` provides the common
[read-only Connection view](connection.md): ID, transport, original peer and the
current HTTP host/slug selection. It is inherited by authorization requests,
environment requests/tasks, principal mappings, local-account templates and
preparation messages. SSH banners, SSH RememberMe notifications and recording
notices also expose their current connection.

This is routing/peer metadata, not proof of authentication. Core/startup templates
and background resource-cleanup contexts have no current connection and do not
fabricate one. Objects describing a stored authorization, recording, container
or pod do not acquire a live connection merely because they contain metadata.

## Variants

<% for child in page.parent.children %>
<% if child != page %>
1. [<<child.title>>](<<rel_file_path(child.file.src_path, page.file.src_path)>>)
<% endif %>
<% endfor %>
