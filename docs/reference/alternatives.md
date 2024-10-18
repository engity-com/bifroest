---
description: Defines how Bifröst reaches alternatives of itself.
---

# Alternatives

Defines how Bifröst reaches alternatives of itself.

For example if itself runs currently runs on AMD64 architecture, but needs for a target system an ARM64 instance. Or if the host is Windows, but the target is Linux.

Especially if a containerized environment (like [Docker environment](environment/docker.md)) is used, some features requires a supporting process that runs directly inside the container to enable all features. Such as tcp portforward from the context of the container or SSH Agent forward.

## Properties

<<property("downloadUrl", "URL", "data-type.md#url", template_context="context/alternative-binary.md", default="https://github.com/engity-com/bifroest/releases/download/v{{.version}}/bifroest-{{.os}}-{{.arch}}-{{.edition}}{{.packageExt}}")>>
URL where to download the alternative version of Bifröst. Usually we simply will get this from [the GitHub Releases of Bifröst](https://github.com/engity-com/bifroest/releases).

<<property("location", "File Path", "data-type.md#file-path", template_context="context/alternative-binary.md", default="<os specific>")>>
Location to store the downloaded alternative version of Bifröst at.

A file that already exists, will not be downloaded again.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/binaries/{{.version}}/{{.os}}-{{.arch}}-{{.edition}}{{.ext}}`
* Window: `C:\ProgramData\Engity\Bifroest\binaries\{{.version}}\{{.os}}-{{.arch}}-{{.edition}}{{.ext}}`
