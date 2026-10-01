---
description: Install Bifröst as a host service with SSH access to existing local accounts.
toc_depth: 3
---

# Installing on host

Bifröst runs as a host service on **port 22**. Sign in with an existing local user; the same [configuration](<<asset_url("contrib/configurations/on-host.yaml")>>) works on all three platforms.

**Port 22 must be free:** stop the existing SSH server first, and keep another way to access the machine.

SSH may warn that the server key changed; verify the change before continuing.

Use the [archive](distribution.md#archive) from the same release as this page. These examples use AMD64 and assume a fresh installation; for other systems see [distributions](distribution.md), for upgrades see the [upgrade notes](upgrade.md).

## Linux

Use the [Linux extended edition](distribution.md#linux-extended) and an existing local user:

```bash
curl -fLsS -o bifroest-linux-amd64-extended.tgz '<<release_asset_url("bifroest-linux-amd64-extended.tgz")>>'
sudo tar -xzf bifroest-linux-amd64-extended.tgz -C /usr/bin bifroest
sudo install -d -m 0750 /etc/engity/bifroest
sudo curl -fLsS -o /etc/engity/bifroest/configuration.yaml '<<asset_url("contrib/configurations/on-host.yaml", True)>>'
sudo curl -fLsS -o /etc/systemd/system/bifroest.service '<<asset_url("contrib/systemd/bifroest.service", True)>>'
sudo systemctl daemon-reload
sudo systemctl enable --now bifroest.service
```

Log in with that user's SSH key or password:

```bash
ssh "$USER@localhost"
```

If login fails, check `sudo journalctl -u bifroest.service`. To revert, run `sudo systemctl disable --now bifroest.service` and restart the previous SSH server.

## Windows

Use the [Windows generic edition](distribution.md#windows-generic) and an existing local user (not a domain account).

```powershell
# Do the following commands in an elevated PowerShell window
$archive = Join-Path $env:TEMP 'bifroest-windows-amd64-generic.zip'
Invoke-WebRequest -Uri '<<release_asset_url("bifroest-windows-amd64-generic.zip")>>' -OutFile $archive
New-Item -ItemType Directory -Force 'C:\Program Files\Engity\Bifroest' | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath 'C:\Program Files\Engity\Bifroest'
New-Item -ItemType Directory -Force 'C:\ProgramData\Engity\Bifroest' | Out-Null
Invoke-WebRequest -Uri '<<asset_url("contrib/configurations/on-host.yaml", True)>>' -OutFile 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
& 'C:\Program Files\Engity\Bifroest\bifroest.exe' service install --configuration 'C:\ProgramData\Engity\Bifroest\configuration.yaml'
```

Log in with that user's SSH key or password:

```powershell
ssh "$env:USERNAME@localhost"
```

If login fails, check Windows Event Viewer. To revert, stop Bifröst with `& 'C:\Program Files\Engity\Bifroest\bifroest.exe' service remove` and restart the previous SSH server.

## macOS

Use the [macOS generic edition](distribution.md#darwin-generic) and an existing local user:

```sh
curl -fLsS -o bifroest-darwin-arm64-generic.tgz '<<release_asset_url("bifroest-darwin-arm64-generic.tgz")>>'
sudo tar -xzf bifroest-darwin-arm64-generic.tgz -C /usr/local/bin bifroest
sudo install -d -o root -g wheel -m 0750 '/Library/Application Support/Engity/Bifroest'
sudo curl -fLsS -o '/Library/Application Support/Engity/Bifroest/configuration.yaml' '<<asset_url("contrib/configurations/on-host.yaml", True)>>'
sudo chown root:wheel '/Library/Application Support/Engity/Bifroest/configuration.yaml'
sudo chmod 0640 '/Library/Application Support/Engity/Bifroest/configuration.yaml'
sudo /usr/local/bin/bifroest service install
```

Log in with that user's SSH key or password:

```sh
ssh "$USER@localhost"
```

If login fails, check the logs in `/Library/Logs/Engity/Bifroest`. To revert, run `sudo /Library/PrivilegedHelperTools/com.engity.bifroest service remove` and re-enable Remote Login.

## Next steps

* Adjust [flows](../reference/flow.md), [local authorization](../reference/authorization/local.md) and [session environments](../reference/environment/index.md) for your access policy.
* Configure [Docker or Kubernetes](in-docker.md) only if you need those environments.
