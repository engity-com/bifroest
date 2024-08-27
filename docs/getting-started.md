---
toc_depth: 2
---

# Getting started

## Installation

1. Download Bifröst (see [release page](<< release_url() >>)):<br>

    #### Syntax
    ```shell
    curl -sSLf {{ release_asset_url("bifroest-<os>-<arch>-<edition>.tgz") }} | sudo tar -zxv -C /usr/bin bifroest
    ```

    #### Matrix

    > Column headers in format of `<os>`/`<edition>`.

    | `arch` | `linux`/`generic` | `linux`/`extended` | `windows`/`generic` | `windows`/`extended` |
    | - | - | - | - | - |
    | `amd64` | :material-checkbox-marked-circle: | :material-checkbox-marked-circle: | :material-checkbox-marked-circle: | :material-circle-outline: |
    | `arm64` | :material-checkbox-marked-circle: | :material-checkbox-marked-circle: | :material-checkbox-marked-circle: | :material-circle-outline: |



    #### Example
    ```shell
    curl -sSLf {{ release_asset_url("bifroest-linux-amd64-extended.tgz") }} | sudo tar -zxv -C /usr/bin bifroest
    ```

2. Configure Bifröst. For example download the demo configuration and adjust for your needs (see [documentation of configuration](documentation/configuration.md) for the documentation about it):
   ```shell
   sudo mkdir -p /etc/engity/bifroest/
   sudo curl -sSLf {{ asset_url("contrib/configurations/sshd-dropin-replacement.yaml", True) }} -o /etc/engity/bifroest/configuration.yaml
   # Adjust it to your needs
   sudo vi /etc/engity/bifroest/configuration.yaml
   ```

3. Run Bifröst:
   ```shell
   sudo bifroest run
   ```

## Autostart

...when the system starts.

### systemd

To enable Bifröst to run at every server start where [systemd](https://wiki.archlinux.org/title/Systemd) is available, simply:
1. Download << asset_link("contrib/systemd/bifroest.service", "our example service configuration") >>:
   ```shell
   sudo curl -sSLf {{ asset_url("contrib/systemd/bifroest.service", True) }} -o /etc/systemd/system/bifroest.service
   ```
2. Reload the systemd daemon:
   ```shell
   sudo systemctl daemon-reload
   ```
3. Enable and start Bifröst:
   ```shell
   sudo systemctl enable bifroest.service
   sudo systemctl start bifroest.service
   ```

## What's next?

Read [Use-Cases](usecases.md) and [the configuration documentation](documentation/configuration.md) to see what you can do more with Bifröst.
