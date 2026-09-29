---
description: Context are used while evaluating templates in Bifröst.
---

# Context objects

Context objects depend on where they are used and are mainly injected into [template evaluation](../templating/index.md). For local account-management templates, see [Context Local Environment](local-environment.md).

## Variants

<% for child in page.parent.children %>
<% if child != page %>
1. [<<child.title>>](<<rel_file_path(child.file.src_path, page.file.src_path)>>)
<% endif %>
<% endfor %>
