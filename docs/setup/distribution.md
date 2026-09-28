---
toc_depth: 4
description: Which kinds of different distribution are available of Bifröst and how to obtain them.
---

# Distributions

Bifröst is available in different distributions.

On this page you'll find:

1. [Operating Systems](#os)
    1. [Linux](#linux)
    2. [macOS](#darwin)
    3. [Windows](#windows)
2. [Packaging](#packaging)
    1. [Archives](#archive)
    2. [OCI/Docker Images](#image)
    3. [Compliance Artifacts](#compliance)

<div id="compatibility"></div>
<<compatibility_matrix()>>
> Cells express support in format of `<generic>`/`<extended>`.

## Operating Systems {: #os}

Bifröst is currently available for [Linux](#linux), [macOS](#darwin) and [Windows](#windows).

### Linux {: #linux}

#### Generic {: #linux-generic}

The generic Linux distribution of Bifröst requires kernel support for `PR_SET_CHILD_SUBREAPER`, which is available since Linux 3.4. The effective minimum kernel can be higher for newer architectures. The binary does not require other shared libraries to be installed, regardless of whether the distribution is Ubuntu, Alpine, RedHat, or another variant. On the other hand, it lacks some features of the [extended version](#linux-extended).

#### Extended {: #linux-extended}

The extended Linux distribution of Bifröst currently only runs on Debian 12+, Ubuntu 22.04+ and Fedora 39+.

It does provide the following features:

1. [PAM authentication](../reference/authorization/local.md#property-pamService) via [Local authorization](../reference/authorization/local.md)

### Dependencies

| Name | Shared-Lib | Version |
| - | - | - |
| [GNU C Library (glibc)](https://www.gnu.org/software/libc/) | `libc.so.6` | 2.34+ |
| [Linux PAM (Pluggable Authentication Modules for Linux)](https://github.com/linux-pam/linux-pam) | `libpam.so.0` | 1.4+ |

##### Installation

* **Debian/Ubuntu**: Usually installed by default, in some cases the following command might be necessary:
   ```shell
   sudo apt install libpam0g -y
   ```
* **RedHat/Fedora**: Already installed by default.

### macOS {: #darwin}

#### Generic {: #darwin-generic}
Not available.

#### Extended {: #darwin-extended}
The extended macOS distribution supports Apple silicon (`arm64`) on macOS 13 and later. No generic macOS distribution is available.

Official macOS release binaries are signed with an Engity Developer ID Application certificate, use the hardened runtime and are accepted by Apple's notarization service before publication. Because the executable is distributed in a `tgz` archive, the first Gatekeeper assessment may need network access to retrieve Apple's notarization ticket. Manual development builds are unsigned unless a Developer ID identity is supplied explicitly and should not be redistributed as official releases.

The supported unattended-installation channel is the archive containing the signed executable and its included system LaunchDaemon management script. A notarized installer package and a Homebrew formula are deferred; Homebrew's versioned prefix and user-oriented service model do not match the current root LaunchDaemon layout.

### Windows {: #windows}

#### Generic {: #windows-generic}
The generic Windows distribution of Bifröst contains all supported features for Windows 10, Windows Server 2016, and later versions. It does not have any requirements on which other shared libraries need to be installed.

#### Extended {: #windows-extended}
Not available.

## Packaging

Bifröst can be either obtained as [Archive which contains the binaries](#archive) or as [OCI/Docker images](#image).

### Archives {: #archive }

Archives contain for every supported operating systems and architecture the binary of Bifröst itself with a basic README, licence information and demo material. It can be simply downloaded, extracted and run.

See the [release page](<< release_url() >>) for all available downloads.

#### Matrix {: #archive-matrix }

<<compatibility_matrix(packaging="archive")>>

#### URL Syntax {: #archive-syntax }

* Linux:
    ```plain
    <<release_asset_url("bifroest-linux-<arch>-<edition>.tgz")>>
    ```
* macOS:
    ```plain
    <<release_asset_url("bifroest-darwin-arm64-extended.tgz")>>
    ```
* Windows:
    ```plain
    <<release_asset_url("bifroest-windows-<arch>-<edition>.zip")>>
    ```

##### Examples {: #archive-examples }

* Linux Extended on AMD64:
    ```shell
    curl -sSLf <<release_asset_url("bifroest-linux-amd64-extended.tgz")>> | sudo tar -zxv -C /usr/bin bifroest
    ```

* macOS Extended on ARM64:
    ```shell
    curl -sSLf <<release_asset_url("bifroest-darwin-arm64-extended.tgz")>> | sudo tar -zxv -C /usr/local/bin bifroest
    ```

* Windows Generic on AMD64:
    ```{.powershell title="Run elevated"}
    mkdir -Force 'C:\Program Files\Engity\Bifroest'
    curl -sSLf -o "${Env:Temp}\bifroest.zip" <<release_asset_url("bifroest-windows-amd64-generic.zip")>>
    Expand-Archive "${Env:Temp}\bifroest.zip" -DestinationPath 'C:\Program Files\Engity\Bifroest'
    ```

### OCI/Docker Images {: #image}

Bifröst is also available in OCI/Docker images. You just need to mount a valid configuration into the container.

There is no Darwin OCI image. On macOS, use the native archive or run a supported Linux image through a container runtime.

See the [container registry page](<< container_packages_url() >>) for all available tags.

#### Matrix {: #image-matrix }

<<compatibility_matrix(packaging="image")>>

#### TAG Syntax {: #image-syntax }

* Generic:
    ```plain
    <<container_image_uri("generic-<major>.<minor>.<patch>")>>
    <<container_image_uri("generic-<major>.<minor>")>>
    <<container_image_uri("generic-<major>")>>
    <<container_image_uri("generic")>>
    <<container_image_uri("<major>.<minor>.<patch>")>>
    <<container_image_uri("<major>.<minor>")>>
    <<container_image_uri("<major>")>>
    <<container_image_uri("latest")>>
    ```

* Extended:
    ```plain
    <<container_image_uri("extended-<major>.<minor>.<patch>")>>
    <<container_image_uri("extended-<major>.<minor>")>>
    <<container_image_uri("extended-<major>")>>
    <<container_image_uri("extended")>>
    ```

##### Examples {: #image-examples }

```shell
<<container_image_uri("*")>>
<<container_image_uri("latest")>>
<<container_image_uri("extended")>>
```

### Compliance Artifacts {: #compliance}

Every release provides platform- and edition-specific third-party notices and
SBOMs alongside its archives. Archive SBOMs describe the downloadable archive;
OCI SBOMs describe the indicated platform image within the multi-platform OCI
index. They are intentionally separate because their package inventories and
subject digests can differ.

The `darwin/arm64/extended` release variant therefore includes
`bifroest-darwin-arm64-extended.tgz`, its `.third-party-notices.txt` file, and
the archive's `.spdx.json` and `.cdx.json` SBOMs. It has no OCI image or OCI
SBOMs.

The [release manifest](<<release_asset_url("bifroest-release-manifest.json")>>)
relates every artifact to its platform, edition, media type and SHA-256 digest.
Use [the checksum file](<<release_asset_url("bifroest-checksums.txt")>>) to verify
all downloadable release assets.

<<compliance_matrix()>>

OCI entries link to the container package. The abbreviated digest identifies
the immutable multi-platform index; the complete index and platform references
are available in the release manifest.
