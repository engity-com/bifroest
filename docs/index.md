---
description: Bifröst is an SSH server with OIDC authorization and configurable local, container and SSH target sessions.
---

# Engity's Bifröst

![Engity's Bifröst](assets/logo-with-text.svg){. class=bifroest-logo title="Logo of Engity's Bifröst with title"}

## SSH access with configurable authorization and session targets

Bifröst lets platform teams combine SSH authorization with the environment in which a session runs. Users connect with a standard SSH client; [OIDC Device Authorization](reference/authorization/oidc.md) also requires a browser and a supported identity provider. Sessions can run on a local account, in a Docker container or Kubernetes Pod, or through a separately authenticated [SSH target](reference/environment/ssh.md). Bifröst is not a universal drop-in replacement for [OpenSSH's sshd](https://man.openbsd.org/sshd).

**Install it as a host service:** the [host guide](setup/on-host.md) starts Bifröst on port 22 with the privileges required to open a real shell as an existing local account. Linux uses systemd, Windows uses a Windows service, and the upcoming release is planned to include a macOS LaunchDaemon.

## Features

### Standard SSH clients

Connect with OpenSSH, PuTTY and other standard SSH clients. Check the [supported operations](reference/environment/ssh.md#supported-operations) and test specialized `sshd` policies before migrating.

### OpenID Connect
Authorize via SSH keys or an [OpenID Connect](https://openid.net/) identity provider. Device Authorization needs a browser verification step, but no separate SSH client application.

#### Docker environments

You can execute your users into individual Docker containers with custom images, network settings, and much more...

#### Kubernetes environments

Be directly inside a dedicated Pod inside your Kubernetes cluster and have access to all of its resources without extra port forwarding.

### Remember me

Once authenticated using a public key, Bifröst can (temporarily) store that public key for faster reconnection while the session is still active.

### Automatic user provisioning

If a user needs to be authorized in a local environment using [OpenID Connect](#openid-connect), Bifröst can automatically create a local user based on a pre-defined requirement template.

Configured policies can clean up managed accounts, homes and processes after sessions end. These operations are not universally enabled by default; review the [local environment settings](reference/environment/local.md#dispose).

### More to come...

## More topics
* [Getting started](setup/index.md)
* [Use-Cases](usecases.md)
* [Configuration](reference/configuration.md)
