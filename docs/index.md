---
description: Bifröst is a highly customizable SSH server with several ways to authorize a user and options where and how to execute a user's session.
---

# Engity's Bifröst

![Engity's Bifröst](assets/logo-with-text.svg){. class=bifroest-logo title="Logo of Engity's Bifröst with title"}

## Welcome

Bifröst (spoken as "Bee-frest"), is a highly customizable SSH server with several ways to authorize a user and where and how to execute its session. It can be used as a drop-in-replacement for [OpenSSH's sshd](https://man.openbsd.org/sshd), but it was actually created with some more advanced stuff in mind; see below.

## Features

### SSH protocol compliant

Fully **[SSH protocol](https://www.rfc-editor.org/rfc/rfc4253) compliant server**, like you would expect.

### OpenID Connect
You can connect via your **SSH keys**, as usually. And so on...

...but you can also use **[OpenID Connect](https://openid.net/)** (or OAuth2) identity provider. The best thing about it: In contrast to the other SSH servers with OpenID Connect you don't need to install another client in addition to your regular SSH Client ([OpenSSH](https://www.openssh.com/), [PuTTy](https://www.putty.org/), ...).

#### Docker environments

You can execute your users into individual Docker containers with custom images, network settings, and much more...

#### Kubernetes environments

Be directly inside a dedicated Pod inside your Kubernetes cluster and have access to all of its resources without extra port forwarding.

### Remember me

Once authenticated using a public key, Bifröst can (temporarily) store that public key for faster reconnection while the session is still active.

### Automatic user provisioning

If a user needs to be authorized in a local environment using [OpenID Connect](#openid-connect), Bifröst can automatically create a local user based on a pre-defined requirement template.

Bifröst can also automatically clean up these local users once they are no longer needed. For example: If their session times out after a defined idle-time, the local user, their home directory, and all running processes can be cleaned up.

### More to come...

## More topics
* [Getting started](setup/index.md)
* [Use-Cases](usecases.md)
* [Configuration](reference/configuration.md)
