---
toc_depth: 4
description: Which kinds of different distribution are available of Bifröst and how to obtain them.
---

# Distributions

Bifröst is available in different distributions.

On this page you'll find:

1. [Operating Systems](#os)
    1. [Linux](#linux)
    2. [Windows](#windows)
2. [Packaging](#packaging)
    1. [Archives](#archive)
    2. [OCI/Docker Images](#image)

<div id="compatibility"></div>
<<compatibility_matrix()>>
> Cells express support in format of `<generic>`/`<extended>`.

## Operating Systems {: #os}

Bifröst is currently available for [Linux](#linux) and [Windows](#windows).

### Linux {: #linux}

#### Generic {: #linux-generic}

The generic Linux distribution of Bifröst contains features that run on every Linux distribution, regardless of Ubuntu, Alpine, RedHat, ... It does not even have any requirements on which other shared libraries need to be installed. On the other hand, it lacks some features of the [extended version](#linux-extended).

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

### Windows {: #windows}

#### Generic {: #windows-generic}
The generic Windows distribution of Bifröst contains all supported features for Windows from Windows 7+ on. It does not even have any requirements on which other shared libraries need to be installed.

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
* Windows:
    ```plain
    <<release_asset_url("bifroest-windows-<arch>-<edition>.zip")>>
    ```

##### Examples {: #archive-examples }

* Linux Extended on AMD64:
    ```shell
    curl -sSLf <<release_asset_url("bifroest-linux-amd64-extended.tgz")>> | sudo tar -zxv -C /usr/bin bifroest
    ```

* Windows Generic on AMD64:
    ```{.powershell title="Run elevated"}
    mkdir -Force 'C:\Program Files\Engity\Bifroest'
    curl -sSLf -o "${Env:Temp}\bifroest.zip" <<release_asset_url("bifroest-windows-amd64-generic.zip")>>
    Expand-Archive "${Env:Temp}\bifroest.zip" -DestinationPath 'C:\Program Files\Engity\Bifroest'
    ```

### OCI/Docker Images {: #image}

Bifröst is also available in OCI/Docker images. You just need to mount a valid configuration into the container.

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
