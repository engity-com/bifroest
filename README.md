# Engity's Bifröst

Bifröst (spoken as "Bee-frest"), is an advanced SSH server. It can be used as a drop-in-replacement for [OpenSSH Server](https://www.openssh.com/), but it was actually created with some more advanced stuff in mind; see below.

## TOC

* [Use-cases](doc/usecases.md)
* [Features](#features)
* [Getting started](#getting-started)
* [Configuration](doc/configuration.md)
* [Status](#status)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security](SECURITY.md)

## Features

1. [SSH protocol complaint](#ssh-protocol-complaint)
2. [OpenID Connect](#openid-connect)
3. [Remember me](#remember-me)
4. [Automatic user provisioning](#automatic-user-provisioning)

#### SSH protocol complaint

Fully **[SSH protocol](https://www.rfc-editor.org/rfc/rfc4253) compliant server**, like you would expect.

#### OpenID Connect
You can connect via your **SSH keys**, as usually. And so on...

...but you can also use **[OpenID Connect](https://openid.net/)** (or OAuth2) identity provider. The best thing about this is: In contrast to the other SSH servers with OpenID Connect, you don't need any other client locally installed, than your regular SSH Client ([OpenSSH](https://www.openssh.com/), [PuTTy](https://www.putty.org/), ...).

#### Remember me

If authorized via another authentication token then a Public Key, it can store (temporally) your provided Public Key, for faster reconnect, while the session is still alive.

#### Automatic user provisioning

If a local environment is used where the user executes inside and [OpenID Connect](#openid-connect) was used to authorize a user, Bifröst can automatically create these users based on a defined requirement template.

It can also automatically clean up these users as they're no longer needed, for example: If their session becoming idle and times out (30 minutes). In this case the user itself, its home directory and all running processes can be cleaned up.

#### More to come...

## Getting started

1. Download the latest version of Bifröst (see [releases page](https://github.com/engity-com/bifroest/releases)):
   ```shell
   # Syntax
   curl -sSLf https://github.com/engity-com/bifroest/releases/download/<version>/bifroest-<os>-<arch>-<edition>.tgz | sudo tar -zxv -C /usr/bin bifroest

   # Example
   curl -sSLf https://github.com/engity-com/bifroest/releases/download/v1.2.3/bifroest-linux-amd64-extended.tgz | sudo tar -zxv -C /usr/bin bifroest
   ```
2. Configure Bifröst. For example download the demo configuration and adjust for your needs (see [documentation of configuration](doc/configuration.md) for the documentation about it):
   ```shell
   sudo mkdir -p /etc/engity/bifroest/
   sudo curl -sSLf https://raw.githubusercontent.com/engity-com/bifroest/main/contrib/configurations/sshd-dropin-replacement.yaml -o /etc/engity/bifroest/configuration.yaml
   # Adjust it to your needs
   sudo vi /etc/engity/bifroest/configuration.yaml
   ```
3. Run Bifröst:
   ```shell
   sudo bifroest run
   ```

### Let it run automatically

#### systemd

To enable Bifröst to run at every server start where [systemd](https://wiki.archlinux.org/title/Systemd) is available, simply:
1. Download [our example service configuration](contrib/systemd/bifroest.service):
   ```shell
   sudo curl -sSLf https://raw.githubusercontent.com/engity-com/bifroest/main/contrib/systemd/bifroest.service -o /etc/systemd/system/bifroest.service
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

### What's next?

Read [Use-Cases](doc/usecases.md) and [the configuration documentation](doc/configuration.md) to see what you can do more with Bifröst.

## Status

This project is currently under development. The application is stable ([file a bug if you find one](https://github.com/engity-com/bifroest/issues/new/choose)), but the configuration/command/API structure needs improvement.

## More topics
* [Use-Cases](doc/usecases.md)
* [Configuration](doc/configuration.md)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security](SECURITY.md)
