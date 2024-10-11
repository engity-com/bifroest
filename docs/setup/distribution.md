---
description: Which kinds of different distribution are available of Bifröst and how to obtain them.
---

# Distributions

Bifröst is available in different distributions.

## Linux {: #linux}

### Generic {: #linux-generic}

The generic Linux distribution of Bifröst contains features that run on every Linux distribution, regardless of Ubuntu, Alpine, RedHat, ... It does not even have any requirements on which other shared libraries need to be installed. On the other hand, it lacks some features the [extended version](#linux-extended) has.

### Extended {: #linux-extended}

The extended Linux distribution of Bifröst currently only runs on Debian 12+, Ubuntu 22.04+ and Fedora 39+.

It does provide the following features:

1. [PAM authentication](../reference/authorization/local.md#property-pamService) via [Local authorization](../reference/authorization/local.md)

### Dependencies

| Name | Shared-Lib | Version |
| - | - | - |
| [GNU C Library (glibc)](https://www.gnu.org/software/libc/) | `libc.so.6` | 2.34+ |
| [Linux PAM (Pluggable Authentication Modules for Linux)](https://github.com/linux-pam/linux-pam) | `libpam.so.0` | 1.4+ |

#### Installation

* **Debian/Ubuntu**: Usually installed by default, in some cases the following command might be necessary:
   ```shell
   sudo apt install libpam0g -y
   ```
* **RedHat/Fedora**: Already installed by default.

## Windows {: #windows}

### Generic {: #windows-generic}
The generic Windows distribution of Bifröst contains all supported features for Windows from Windows 7+ on. It does not even have any requirements on which other shared libraries need to be installed.

### Extended {: #windows-extended}
Not available.

## Matrix

!!! tip ""
    Cells express support in format of `<generic>`/`<extended>`.

<<compatibility_matrix()>>

## Ways to obtain

### Binary

* Linux:
    ```shell
    curl -sSLf <<release_asset_url("bifroest-linux-<arch>-<edition>.tgz")>> | sudo tar -zxv -C /usr/bin bifroest
    ```
* Windows:
    ```{.powershell title="Run elevated"}
    mkdir -Force 'C:\Program Files\Engity\Bifroest'
    cd 'C:\Program Files\Engity\Bifroest'
    curl -sSLf -o "${Env:Temp}\bifroest.zip" <<release_asset_url("bifroest-windows-<arch>-<edition>.zip")>>
    Expand-Archive "${Env:Temp}\bifroest.zip" -DestinationPath .
    ```
