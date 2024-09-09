---
description: Which kinds of different distribution are available of Bifröst and how to obtain them.
---

# Distributions

Bifröst is available in different distributions.

## Linux {: #linux}

### Generic {: #linux-generic}

The generic Linux distribution of Bifröst contains features that run on every Linux distribution, regardless of Ubuntu, Alpine, RedHat, ... It does not even have any requirements on which other shared libraries need to be installed. On the other hand, it lacks some features the [extended version](#linux-extended) has.

### Extended {: #linux-extended}

The extended Linux distribution of Bifröst currently only runs on Ubuntu 22.04+. It also requires some libraries that are installed:

```shell
sudo apt install libpam0g -y
```

On the other hand, it provides additional features like:

1. [PAM authentication](../reference/authorization/local.md#property-pamService) via [Local authorization](../reference/authorization/local.md)
2. Support of [yescrypt](../reference/authorization/local.md#password-yescrypt) for `/etc/shadow` files, used for [Local authorization](../reference/authorization/local.md).

## Windows {: #windows}

### Generic {: #windows-generic}
The generic Windows distribution of Bifröst contains all supported features for Windows from Windows 7+ on. It does not even have any requirements on which other shared libraries need to be installed.

### Extended {: #windows-extended}
Currently, not available.

## Matrix

| Architecture | [`linux`<br>`generic`](#linux-generic) | [`linux`<br>`extended`](#linux-extended) | [`windows`<br>`generic`](#windows-generic) | [`windows`<br>`extended`](#windows-extended) |
| - | - | - | - | - |
| `amd64` | :octicons-check-circle-24: | :octicons-check-circle-24: | :octicons-check-circle-24: | :octicons-circle-24: |
| `arm64` | :octicons-check-circle-24: | :octicons-check-circle-24: | :octicons-check-circle-24: | :octicons-circle-24: |

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
