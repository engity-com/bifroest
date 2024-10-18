---
description: In cases when Bifröst needs to obtain an alternative variant of its binaries, this context provides the required information.
---

# Context Alternative Binary

In cases when Bifröst needs to obtain an alternative variant of its binaries, this context provides the required information.

## Properties

<<property("os", "string")>>

Holds the name of the operating system, such as `linux` or `windows`.

<<property("arch", "string")>>

Holds the name of the architecture, such as `amd64` or `arm64`.

<<property("version", "string")>>

Holds the actual version, such as `<<release_name()>>`.

<<property("ext", "string")>>

Holds the extension for the target binary, such as `<empty>` or `.exe`.

<<property("packageExt", "string")>>

Holds the extension for the package, such as `.tgz` or `.zip`.
