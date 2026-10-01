---
title: Bifröst SSH server and gateway
description: Use standard SSH clients with OIDC Device Authorization, SSH gateways and Docker/Kubernetes sessions. Verify optional audit and recordings.
---

# Engity's Bifröst

![Engity's Bifröst](assets/logo-with-text.svg){. class=bifroest-logo title="Logo of Engity's Bifröst with title"}

## SSH access with identity and session control

Bifröst lets platform teams combine SSH authorization with the environment in which a session runs. Users connect with a standard SSH client; [OIDC Device Authorization](reference/authorization/oidc.md) also requires a browser and a supported identity provider. Sessions can run on a local account, in a Docker container or Kubernetes Pod, or through a separately authenticated [SSH target](reference/environment/ssh.md). Bifröst is not a universal drop-in replacement for [OpenSSH's sshd](https://man.openbsd.org/sshd).

Bifröst was created for teams with [time-bound off-boarding requirements](usecases.md#offboard), whether the target is 15 minutes, 60 minutes or another defined limit. Meeting it depends on the IdP, bounded access and checks of existing connections.

**Install it as a host service:** the [host guide](setup/on-host.md) starts Bifröst on port 22 with the privileges required to open a real shell as an existing local account. Linux uses systemd, Windows uses a Windows service, and the upcoming release is planned to include a macOS LaunchDaemon.

## Choose your task

* [Connect to a private OpenSSH server](guides/ssh-gateway.md) through an SSH gateway.
* [Log in with OIDC](guides/oidc.md) using an SSH client and a browser verification step.
* [Verify a session recording](guides/recording.md) and export the recorded output.

## Features

### SSH access with your identity

Connect using OpenSSH, PuTTY or another standard SSH client. Authorize with local accounts, SSH keys or [OIDC Device Authorization](guides/oidc.md); OIDC adds a browser verification step, not a separate SSH client.

### Choose where sessions run

Open a shell on the [host](reference/environment/local.md), in a [Docker container](reference/environment/docker.md) or in a [Kubernetes Pod](reference/environment/kubernetes.md). Flows combine the authorization method and session environment; container isolation depends on the permissions you grant.

### SSH gateway to private servers

Connect through Bifröst to an existing SSH server. The [gateway](guides/ssh-gateway.md) verifies the target host key and authenticates to it separately; it does not transparently proxy every SSH request.

### Verifiable audit and recording

Optionally sign [audit events](reference/auditlog/index.md) and [terminal recordings](guides/recording.md) for later verification. Recording captures terminal output, not raw keyboard input or SFTP and forwarding payloads.

### Bound access over time

Set maximum [connection](reference/connection/ssh.md#property-maxTimeout) and [session](reference/session/fs.md#property-maxTimeout) lifetimes, and optionally provision or clean up [local accounts](reference/environment/local.md#account-management). A remembered public key can simplify reconnects while its session remains valid; [time-bound off-boarding](usecases.md#offboard) still needs an end-to-end check.

## More topics
* [Getting started](setup/index.md)
* [Use-Cases](usecases.md)
* [Choosing Bifröst](choosing-bifroest.md)
* [Security and trust](security.md)
* [Configuration](reference/configuration.md)
