# Engity's Bifröst

![Engity's Bifröst](docs/assets/logo-with-text.svg)

Bifröst is an SSH server for teams that need to control how users authenticate and where their sessions run. Configurable flows connect authorization (including OIDC Device Authorization) to local, Docker, Kubernetes, or SSH target environments. Users connect with a standard SSH client; OIDC Device Authorization also requires a browser and a configured identity provider. Bifröst does not replace every `sshd` setup without changes.

## TOC

* [Use-cases](https://bifroest.engity.org/usecases/)
* [Features](#features)
* [Install on a host](#install-on-a-host)
* [Configuration](https://bifroest.engity.org/reference/configuration/)
* [Status](#status)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security](SECURITY.md)

## Install on a host

The [host installation guide](docs/setup/on-host.md) sets up Bifröst as an SSH service on port 22 and logs into an existing local account on Linux (systemd) or Windows (Windows Service). The upcoming release is also intended to support macOS (LaunchDaemon) after [PR #580](https://github.com/engity-com/bifroest/pull/580) is merged and validated. Use the [documentation matching your release](https://bifroest.engity.org/setup/on-host/) and its [assets](https://github.com/engity-com/bifroest/releases); unreleased `main` features are not necessarily in the latest stable binary.

## Features

1. [Standard SSH clients](#standard-ssh-clients)
2. [OpenID Connect](#openid-connect)
3. [Docker environments](#docker-environments)
4. [Kubernetes environments](#kubernetes-environments)
5. [Remember me](#remember-me)
6. [Automatic user provisioning](#automatic-user-provisioning)

#### Standard SSH clients

Connect using an SSH client such as [OpenSSH](https://www.openssh.com/) or [PuTTY](https://www.putty.org/). Not every `sshd` setting is compatible; read the [host installation guide](docs/setup/on-host.md) before replacing an existing SSH server.

#### OpenID Connect
Authorize SSH access with keys or an [OpenID Connect](https://openid.net/) identity provider. Device Authorization works with a standard SSH client, but the user must open a verification page in a browser and the identity provider must support and allow this flow.

#### Docker environments

You can execute your users into individual Docker containers with custom images, network settings, and much more...

#### Kubernetes environments

Be directly inside a dedicated Pod inside your Kubernetes cluster and have access to all of its resources without extra port forwarding.

#### Remember me

After an authorization such as OIDC, Bifröst can temporarily remember a presented public key for faster reconnects while the session is valid. Account revocation and existing connections require separate consideration.

#### Automatic user provisioning

If a local environment is used where the user executes inside and [OpenID Connect](#openid-connect) was used to authorize a user, Bifröst can automatically create these users based on a defined requirement template.

When configured for it, a local environment can create accounts for authorized users and clean them up after sessions end. Cleanup is policy-dependent, not a blanket default; see the [local environment reference](docs/reference/environment/local.md).

#### More to come...

## What's next?

Read the [use cases](https://bifroest.engity.org/usecases/), the [installation guide](https://bifroest.engity.org/setup/) and the [configuration reference](https://bifroest.engity.org/reference/configuration/) for more detail. The source tree also contains [SSH target](docs/reference/environment/ssh.md) and [audit/recording](docs/reference/auditlog/index.md) documentation; check the selected release before relying on these features.

## Status

The latest stable release and its [documentation](https://bifroest.engity.org/) can differ from unreleased `main`. Configuration, commands and APIs may still change; review the [upgrade notes](https://bifroest.engity.org/setup/upgrade/) for the version you plan to install and [report bugs](https://github.com/engity-com/bifroest/issues/new/choose).

For alpha and beta builds, use the exact version from [GitHub Releases](https://github.com/engity-com/bifroest/releases) and its matching versioned documentation. Container images for prereleases use only full version tags such as `:1.0.0-beta1`; `:latest` and other moving tags refer to stable releases.

## More topics
* [Use-Cases](https://bifroest.engity.org/usecases/)
* [Getting started](https://bifroest.engity.org/setup/)
* [Configuration](https://bifroest.engity.org/reference/configuration/)
* [License](LICENSE)
* [Code of Conduct](CODE_OF_CONDUCT.md)
* [Contributing](CONTRIBUTING.md)
* [Security](SECURITY.md)
