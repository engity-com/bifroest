---
description: How to install, configure and run Bifröst directly on the host machine.
toc_depth: 3
---

# Installing on host

!!! tip
     This guide shows how to install Bifröst from [downloadable archive](distribution.md#archive). If you like to use Bifröst inside Docker/Container, see our documentation for [OCI/Docker Images](in-docker.md).

## Linux

!!! note
     This guide assumes you have a Linux distribution with [systemd](https://systemd.io/) running. This reflects the majority of all actual distributions, such as Ubuntu, Debian, Fedora, ...

1. Download Bifröst (see [release page](<< release_url() >>)):<br>

    #### Syntax
    ```shell
    curl -sSLf <<release_asset_url("bifroest-windows-<arch>-<edition>.tgz")>> | sudo tar -zxv -C /usr/bin bifroest
    ```

    #### Matrix

    !!! tip ""
         Cells express support in format of `<generic>`/`<extended>`. See our [documentation of distributions of Bifröst](distribution.md#linux) to learn more.

    <<compatibility_matrix(os="linux", packaging="archive")>>

    #### Example - Linux AMD64
    ```shell
    curl -sSLf <<release_asset_url("bifroest-linux-amd64-extended.tgz")>> | sudo tar -zxv -C /usr/bin bifroest
    ```

2. Configure Bifröst. For example download the demo configuration and adjust it to your needs (see [documentation of configuration](../reference/configuration.md) for the documentation about it):
   ```shell
   sudo mkdir -p /etc/engity/bifroest/
   sudo curl -sSLf <<asset_url("contrib/configurations/sshd-dropin-replacement.yaml", True)>> -o /etc/engity/bifroest/configuration.yaml
   # Adjust it to your needs
   sudo vi /etc/engity/bifroest/configuration.yaml
   ```

3. Download <<asset_link("contrib/systemd/bifroest.service", "our example service configuration")>>:
   ```shell
   sudo curl -sSLf <<asset_url("contrib/systemd/bifroest.service", True)>> -o /etc/systemd/system/bifroest.service
   ```

4. Reload the systemd daemon:
   ```shell
   sudo systemctl daemon-reload
   ```

5. Enable and start Bifröst:
   ```shell
   sudo systemctl enable bifroest.service
   sudo systemctl start bifroest.service
   ```

6. Now you can log in to Bifröst the first time:
   ```shell
   ssh demo@localhost
   ```

## Windows

1. Open a Powershell Terminal with Administrator privileges.

2. Download and extract Bifröst (see [release page](<< release_url() >>)):<br>

    #### Syntax
    ```powershell
    curl -sSLf <<release_asset_url("bifroest-windows-<arch>-<edition>.zip")>> -o "${Env:Temp}\bifroest.zip"
    mkdir -Force 'C:\Program Files\Engity\Bifroest'
    Expand-Archive "${Env:Temp}\bifroest.zip" -DestinationPath 'C:\Program Files\Engity\Bifroest'
    ```

    #### Matrix

    !!! tip ""
         Cells express support in format of `<generic>`/`<extended>`. See our [documentation of distributions of Bifröst](distribution.md#windows) to learn more.

    <<compatibility_matrix(os="windows", packaging="archive")>>

    #### Example - Windows AMD64
    ```powershell
    curl -sSLf <<release_asset_url("bifroest-windows-amd64-generic.zip")>> -o "${Env:Temp}\bifroest.zip"
    mkdir -Force 'C:\Program Files\Engity\Bifroest'
    Expand-Archive "${Env:Temp}\bifroest.zip" -DestinationPath 'C:\Program Files\Engity\Bifroest'
    ```

3. Configure Bifröst. For example download the demo configuration and adjust it to your needs (see [documentation of configuration](../reference/configuration.md) for the documentation about it):
   ```powershell
   mkdir -Force 'C:\ProgramData\Engity\Bifroest'
   curl -sSLf <<asset_url("contrib/configurations/dummy-windows.yaml", True)>> -o 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
   # Adjust it to your needs
   notepad 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
   ```

4. Enable and start Bifröst:
   ```powershell
   'C:\Program Files\Engity\Bifroest\bifroest.exe' service install
   ```

5. Now you can log in to Bifröst the first time:
   ```powershell
   ssh demo@localhost
   ```

## What's next?

* [Configuration details](../reference/configuration.md)
* [Install in Docker](in-docker.md)
