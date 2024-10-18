---
description: How to install, configure and run Bifröst inside Docker.
toc_depth: 2
---

# Installing in Docker

!!! tip
     This guide shows how to install Bifröst in Docker/Container. If you like to use Bifröst directly on your Host, see its documentation [here](on-host.md).

## Before we start

Be sure Bifröst is supporting your Docker host, by checking the following matrix:<br>

!!! tip ""
     Cells express support in format of `<generic>`/`<extended>`. See our [documentation of distributions of Bifröst](distribution.md) to learn more.

<<compatibility_matrix(packaging="archive")>>

In the majority of the cases you might run Linux or Windows on AMD64, which is supported.

## Linux

!!! note
     This guide assumes you have a Linux distribution with [systemd](https://systemd.io/) running. This reflects the majority of all actual distributions, such as Ubuntu, Debian, Fedora, ...

1. [Ensure you have a working docker instance installed.](https://docs.docker.com/engine/install/)

2. Configure Bifröst. For example download the demo configuration and adjust it to your needs (see [documentation of configuration](../reference/configuration.md) for the documentation about it):
   ```shell
   sudo mkdir -p /etc/engity/bifroest/
   sudo curl -sSLf <<asset_url("contrib/configurations/simple-inside-docker.yaml", True)>> -o /etc/engity/bifroest/configuration.yaml
   # Adjust it to your needs
   sudo vi /etc/engity/bifroest/configuration.yaml
   ```

3. Enable Bifröst to always run on your system, by downloading <<asset_link("contrib/systemd/bifroest-in-docker.service", "our example service configuration")>>:
   ```shell
   sudo curl -sSLf <<asset_url("contrib/systemd/bifroest-in-docker.service", True)>> -o /etc/systemd/system/bifroest.service
   # Adjust it to your needs
   sudo vi /etc/systemd/system/bifroest.service
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

6. If you're using the [original demo configuration](<<asset_url("contrib/configurations/simple-inside-docker.yaml")>>), Bifröst will print a demo password to its log files while startup. You can receive it with the following command:
   ```shell
   docker logs bifroest
   ```

7. Now you can log in to Bifröst the first time:
   ```shell
   ssh demo@localhost
   ```

## Windows

1. [Ensure you have a working docker instance installed.](https://docs.docker.com/engine/install/)

    !!! note
         This guide assumes you're running a Linux host of Docker on Docker for Windows (default).

         Bifröst also supports Windows Containers (Windows native). You just have to adjust the path below accordingly.

2. Open a Powershell Terminal with Administrator privileges.

3. Configure Bifröst. For example download the demo configuration and adjust it to your needs (see [documentation of configuration](../reference/configuration.md) for the documentation about it):
   ```powershell
   mkdir -Force 'C:\ProgramData\Engity\Bifroest'
   curl -sSLf <<asset_url("contrib/configurations/dummy-windows.yaml", True)>> -o 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
   # Adjust it to your needs
   notepad 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
   ```

4. Enable and start Bifröst:
   ```shell
   docker run -d --restart unless-stopped --name bifroest -p 22:22 -v //var/run/docker.sock:/var/run/docker.sock -v C:\ProgramData\Engity\Bifroest:/etc/engity/bifroest -v C:\ProgramData\Engity\Bifroest:/var/lib/engity/bifroest ghcr.io/engity-com/bifroest:latest run --log.colorMode=always
   ```

5. Now you can log in to Bifröst the first time:
   ```shell
   ssh demo@localhost
   ```

## What's next?

* [Configuration details](../reference/configuration.md)
* [Install on Host](on-host.md)
