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

## macOS

This guide supports Intel (`amd64`) and Apple silicon (`arm64`) on macOS 13 and later.

!!! warning
     Bifröst uses the standard SSH port `22`. If macOS Remote Login already occupies that port, Bifröst fails to start. Disable Remote Login before installing the LaunchDaemon.

1. Download and install the generic Bifröst archive:
    ```shell
    rm -rf /tmp/bifroest-release
    mkdir -p /tmp/bifroest-release
    case "$(uname -m)" in
      arm64)
        archive=bifroest-darwin-arm64-generic.tgz
        archive_url=<<release_asset_url("bifroest-darwin-arm64-generic.tgz")>>
        ;;
      x86_64)
        archive=bifroest-darwin-amd64-generic.tgz
        archive_url=<<release_asset_url("bifroest-darwin-amd64-generic.tgz")>>
        ;;
      *) echo "Unsupported macOS architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    curl -sSLf "${archive_url}" -o "/tmp/${archive}"
    curl -sSLf <<release_asset_url("bifroest-checksums.txt")>> -o /tmp/bifroest-checksums.txt
    (cd /tmp && grep "  ${archive}$" bifroest-checksums.txt | shasum -a 256 --check -)
    tar -zxvf "/tmp/${archive}" -C /tmp/bifroest-release
    ```

2. Create the native configuration directory and install the [SSHD replacement example](<<asset_url("contrib/configurations/sshd-dropin-replacement.yaml")>>) (see the [configuration documentation](../reference/configuration.md)):
    ```shell
    sudo install -d -o root -g wheel -m 0750 '/Library/Application Support/Engity/Bifroest'
    sudo curl -sSLf <<asset_url("contrib/configurations/sshd-dropin-replacement.yaml", True)>> -o '/Library/Application Support/Engity/Bifroest/configuration.yaml'
    sudo vi '/Library/Application Support/Engity/Bifroest/configuration.yaml'
    sudo chown root:wheel '/Library/Application Support/Engity/Bifroest/configuration.yaml'
    sudo chmod 0640 '/Library/Application Support/Engity/Bifroest/configuration.yaml'
    ```

3. Install and start the system LaunchDaemon:
    ```shell
    sudo /tmp/bifroest-release/bifroest service install
    ```

    The service runs as `root`, starts at boot, restarts after failures and writes standard output and error to `/Library/Logs/Engity/Bifroest`. Root is required for account management and impersonation. Only records in the local `/Local/Default` Directory Services node are mutated; newly created accounts do not receive a local password from Bifröst. Its working directory and persistent state remain under `/Library/Application Support/Engity/Bifroest`.

4. In another terminal, log in using the configured port:
    ```shell
    ssh <local-account>@localhost
    ```

### Manage the macOS service

Run `service install` from an extracted newer archive to stop the service, atomically replace the binary and LaunchDaemon definition, and start it again:

```shell
sudo /tmp/bifroest-release/bifroest service install
```

The installed CLI supports `start`, `stop` and `remove`. `remove` stops the LaunchDaemon and removes its definition and `/Library/PrivilegedHelperTools/com.engity.bifroest`, but deliberately preserves configuration, keys, audit data and recordings under `/Library/Application Support/Engity/Bifroest` as well as logs under `/Library/Logs/Engity/Bifroest`:

```shell
sudo /Library/PrivilegedHelperTools/com.engity.bifroest service stop
sudo /Library/PrivilegedHelperTools/com.engity.bifroest service start
sudo /Library/PrivilegedHelperTools/com.engity.bifroest service remove
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
