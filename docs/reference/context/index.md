---
description: Context are used while evaluating templates in Bifröst.
---

# Context objects

Context objects depends on where they are used in 😉 and mainly injected into a [template evaluation](../templating/index.md).

## Variants

<% for child in page.parent.children %>
<% if child != page %>
1. [<<child.title>>](<<rel_file_path(child.file.src_path, page.file.src_path)>>)
<% endif %>
<% endfor %>

