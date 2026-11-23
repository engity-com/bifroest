---
toc_depth: 4
description: Download Bifröst packages and select container images or a Helm chart for this release.
---

# Downloads and distributions

**Downloads for <<release_name()>>.** Choose an installation method, then select the package or image for your platform. Updating an existing installation? Read the [upgrade notes](upgrade.md).

| Installation | Distribution | Instructions |
| --- | --- | --- |
| Host service on Linux, macOS or Windows | [Download an archive](#archive) | [Install on host](on-host.md) |
| Docker or another container runtime | [OCI/Docker images](#image) | [Install in Docker](in-docker.md) |
| Kubernetes | [Helm chart](#helm) | [Install with Helm](in-kubernetes.md) |
| GitHub Actions job | [Archives via Setup Bifröst](#archive) | [Use in GitHub Actions](github-actions.md) |

## Downloads {: #packaging}

### Archives {: #archive }

Archives include the executable, README, configuration examples, license texts and `THIRD_PARTY_NOTICES.txt`. For Linux local-account password authentication through PAM, choose [Extended](#linux-extended); choose [Generic](#linux-generic) when you do not need PAM and want no additional shared-library dependencies.

For a GitHub Actions job, [Setup Bifröst](github-actions.md) downloads and verifies the matching archive and adds the executable to `PATH` for you.

<div id="archive-matrix"></div>
<div id="archive-syntax"></div>
<div id="archive-examples"></div>

<<compatibility_matrix(packaging="archive", downloads=True)>>

Each cell shows **Generic / Extended** download icons, in that order. An empty circle means that edition is not available. Hover or focus a download icon to identify the package.

Verify the download against [the SHA-256 checksum file](<<release_asset_url("bifroest-checksums.txt")>>), then follow [the host installation guide](on-host.md). All release files, including [SBOMs](#compliance), remain available on [GitHub](<<release_url()>>).

### OCI/Docker Images {: #image}

Use the image matching this documentation version and mount your configuration as described in [the Docker installation guide](in-docker.md).

<div id="image-syntax"></div>
<div id="image-examples"></div>

```sh title="Generic"
docker pull <<container_image_uri("generic*")>>
```

```sh title="Extended"
docker pull <<container_image_uri("extended*")>>
```

Full version tags, including alpha/beta suffixes, select a release. Moving tags such as `latest`, `generic`, `extended`, and major/minor aliases refer only to stable releases. See [the container registry](<<container_packages_url()>>) for all tags and [the compliance table](#compliance) for immutable image references.

#### Supported images {: #image-matrix }

<<compatibility_matrix(packaging="image")>>

Cells show Generic/Extended support; an empty circle means that edition is not distributed for the platform.

### Helm Chart {: #helm}

Use `oci://ghcr.io/engity-com/bifroest` with the full release version, without the leading `v`:

```sh
helm pull oci://ghcr.io/engity-com/bifroest --version <<release_name().removeprefix("v") if release_name() != "latest" else "<version>">>
```

The chart version matches the application version, including alpha/beta suffixes. See [Installing in Kubernetes with Helm](in-kubernetes.md) for prerequisites, configuration and a first login. The packaged chart is also available on [the release page](<<release_url()>>).

## Platforms and editions {: #os}

<div id="compatibility"></div>

<<compatibility_matrix()>>

Cells show Generic/Extended support for binaries and images. An empty circle means that edition is not distributed for the platform.

### Linux {: #linux}

#### Generic {: #linux-generic}

The generic binary requires kernel support for `PR_SET_CHILD_SUBREAPER`, available since Linux 3.4. The effective minimum kernel can be higher for newer architectures. It requires no additional shared libraries, but does not support PAM authentication.

#### Extended {: #linux-extended}

The extended binary supports [PAM authentication](../reference/authorization/local.md#property-pamService) and runs on Debian 12+, Ubuntu 22.04+ and Fedora 39+ with these dependencies:

| Dependency | Shared library | Version |
| --- | --- | --- |
| [GNU C Library](https://www.gnu.org/software/libc/) | `libc.so.6` | 2.34+ |
| [Linux PAM](https://github.com/linux-pam/linux-pam) | `libpam.so.0` | 1.4+ |

PAM is normally installed already. If it is missing on Debian/Ubuntu, install it with `sudo apt install libpam0g`.

### macOS {: #darwin}

#### Generic {: #darwin-generic}

Requires macOS 13 or later, with no additional shared-library dependencies.

<div id="darwin-extended"></div>

### Windows {: #windows}

#### Generic {: #windows-generic}

Requires Windows 10, Windows Server 2016, or later, with no additional shared-library dependencies.

<div id="windows-extended"></div>

## Checksums, licenses and SBOMs {: #compliance}

Every archive and container image includes `LICENSE`, the applicable license texts in `LICENSES/`, and its own `THIRD_PARTY_NOTICES.txt`, including notices for the [browser components](../legal/license.md#embedded-browser-components). In archives these files are at the top level; Linux images store them in `/usr/share/licenses/bifroest/`, Windows images in `C:\Program Files\Engity\Bifroest\`.

Separate SPDX and CycloneDX SBOMs describe each downloadable archive and each platform image. Archive and image SBOMs remain distinct because their contents and subject digests can differ.

The [release manifest](<<release_asset_url("bifroest-release-manifest.json")>>) relates downloads and images to their platform, edition, media type and SHA-256 digest. Use [the checksum file](<<release_asset_url("bifroest-checksums.txt")>>) to verify downloadable release assets.

Each entry shows **Generic / Extended**, in that order. An empty circle means the artifact is not available. Hover or focus an icon to identify the platform, edition and artifact.

### Archive files {: #archive-compliance}

<<compliance_matrix(packaging="archive")>>

### OCI images {: #image-compliance}

<<compliance_matrix(packaging="image")>>

OCI reference buttons copy the platform-specific image reference, including its immutable digest, when available. The container package opens if copying is unavailable. Full platform and multi-platform index references are also available in the release manifest.
