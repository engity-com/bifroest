---
description: Imp is a supporting process in for Bifröst to bridge context boundaries, for example to enable port-forwarding into an OCI container.
---

# Imp

Imp is a supporting process in for Bifröst to bridge context boundaries, for example to enable port-forwarding into an OCI container.

Especially if a containerized environment (like [Docker environment](environment/docker.md)) is used, some features requires a supporting process that runs directly inside the container to enable all features. Such as tcp portforward from the context of the container or SSH Agent forward.

## Properties

<<property_with_holder("alternativesDownloadUrl", "URL Template", "templating/index.md#url", "Alternative Binary", "context/alternative-binary.md", default="https://github.com/engity-com/bifroest/releases/download/v{{.version}}/bifroest-{{.os}}-{{.arch}}-generic{{.packageExt}}")>>
URL where to download the alternative version of Bifröst. Usually we simply will get this from [the GitHub Releases of Bifröst](https://github.com/engity-com/bifroest/releases).

<<property_with_holder("alternativesLocation", "String Template", "templating/index.md#string", "Alternative Binary", "context/alternative-binary.md", default="<os specific>")>>
Location to store the downloaded alternative version of Bifröst at.

A file that already exists, will not be downloaded again.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/imp/binaries/{{.version}}/{{.os}}-{{.arch}}{{.ext}}`
* Window: `C:\ProgramData\Engity\Bifroest\imp\binaries\{{.version}}\{{.os}}-{{.arch}}{{.ext}}`
