---
title: Bifröst SSH server and gateway
description: Use SSH clients or optional HTTPS browser access with configurable authorization and session environments. Verify optional audit and recordings.
---

# Engity's Bifröst

![Engity's Bifröst](assets/logo-with-text.svg){. class=bifroest-logo title="Logo of Engity's Bifröst with title"}

## SSH access, your identities, your environments

Bifröst connects [standard SSH clients](reference/connection/ssh.md) or an optional [browser terminal](guides/browser-access.md) to [hosts](reference/environment/local.md), [containers](reference/environment/docker.md), [Kubernetes Pods](reference/environment/kubernetes.md) and [private SSH servers](guides/ssh-gateway.md).

Use an [IdP](reference/authorization/oidc/index.md), [local accounts](reference/authorization/local.md) or [accounts defined in YAML](reference/authorization/simple.md).

**Config-first, testable, simple to deploy** — [version rules, test changes and deploy with your existing tools](concept.md).

Start with a [host service](setup/on-host.md), [Docker](setup/in-docker.md) or [Kubernetes with Helm](setup/in-kubernetes.md).

## Choose your task

* [Connect to a private OpenSSH server](guides/ssh-gateway.md) through an SSH gateway.
* [Log in with OIDC](guides/oidc.md) using an SSH client and a browser verification step.
* [Open a terminal in your browser](guides/browser-access.md) with an existing local account.
* [Verify a session recording](guides/recording.md) and export the recorded output.
* [Test a configuration](guides/testing.md) offline before deployment, locally or in [GitHub Actions](setup/github-actions.md#configuration-tests).

## Features

### SSH access with your identity

Connect using OpenSSH, PuTTY or another standard SSH client, with the identity source and credentials configured for your [flow](reference/flow.md).

### Choose where sessions run

Open a shell on the [host](reference/environment/local.md), in a [Docker container](reference/environment/docker.md) or in a [Kubernetes Pod](reference/environment/kubernetes.md). [Flows](reference/flow.md) combine the [authorization method](reference/authorization/index.md) and [session environment](reference/environment/index.md); container isolation depends on the permissions you grant.

### SSH gateway to private servers

Connect through Bifröst to an existing SSH server. The [gateway](guides/ssh-gateway.md) verifies the target host key and authenticates to it separately; it does not transparently proxy every SSH request.

### Verifiable audit and recording

Optionally sign [audit events](reference/auditlog/index.md) and [terminal recordings](guides/recording.md) for later verification in the CLI or browser. Recording captures terminal output, not raw keyboard input or SFTP and forwarding payloads.

### Bound access over time

Set maximum [SSH connection](reference/connection/ssh.md#property-maxTimeout) and [session](reference/session/fs.md#property-maxTimeout) lifetimes, and optionally provision or clean up [local accounts](reference/environment/local.md#account-management). OIDC's default policy checks [refresh grants](reference/authorization/oidc/authorization-code.md#refresh-token) even for sessions reused with a [remembered public key](reference/data-type.md#rememberme) and closes Bifröst connections after a grant is permanently rejected. [Time-bound off-boarding](usecases.md#offboard) still needs an end-to-end check.

## More topics
* [Getting started](setup/index.md)
* [Use-Cases](usecases.md)
* [Choosing Bifröst](choosing-bifroest.md)
* [Security and trust](security.md)
* [Operations and availability](setup/operations.md)
* [Configuration](reference/configuration.md)
