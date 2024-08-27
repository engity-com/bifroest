# Engity's Bifröst

## Welcome

Bifröst (spoken as "Bee-frest"), is a highly customizable SSH server with several way to authorize a user and where and how to execute its session. It can be used as a drop-in-replacement for [OpenSSH's sshd](https://man.openbsd.org/sshd), but it was actually created with some more advanced stuff in mind; see below.

## Features

### SSH protocol complaint

Fully **[SSH protocol](https://www.rfc-editor.org/rfc/rfc4253) compliant server**, like you would expect.

### OpenID Connect
You can connect via your **SSH keys**, as usually. And so on...

...but you can also use **[OpenID Connect](https://openid.net/)** (or OAuth2) identity provider. The best thing about this is: In contrast to the other SSH servers with OpenID Connect, you don't need any other client locally installed, than your regular SSH Client ([OpenSSH](https://www.openssh.com/), [PuTTy](https://www.putty.org/), ...).

### Remember me

If authorized via another authentication token then a Public Key, it can store (temporally) your provided Public Key, for faster reconnect, while the session is still alive.

### Automatic user provisioning

If a local environment is used where the user executes inside and [OpenID Connect](#openid-connect) was used to authorize a user, Bifröst can automatically create these users based on a defined requirement template.

It can also automatically clean up these users as they're no longer needed, for example: If their session becoming idle and times out (30 minutes). In this case the user itself, its home directory and all running processes can be cleaned up.

### More to come...

## More topics
* [Getting started](getting-started.md)
* [Use-Cases](usecases.md)
* [Configuration](documentation/configuration.md)
