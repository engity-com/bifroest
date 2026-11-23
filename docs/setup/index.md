---
description: How to get started with Bifröst? How to install, configure and run it.
toc_depth: 2
---

# Getting started

Bifröst is available as a host binary, an OCI/Docker image, or a Helm chart for Kubernetes.

For OIDC login, an SSH gateway or session recording, see the [task guides](../guides/index.md).

For production and HA deployments, see the [operating model and availability guide](operations.md): TCP load balancing, instance-local state and recovery.

Before we get started, you need to choose your operating mode. Here are the main differences to help you decide:

| Deployment | Use it when | Prerequisites |
| --- | --- | --- |
| [On host](on-host.md) | Bifröst should run as a system service, including access to local accounts. | A supported host and the service privileges required by your flows. |
| [In Docker](in-docker.md) | You already operate container services. | Docker, mounted configuration and durable storage; runtime access only if your flows need it. |
| [In Kubernetes with Helm](in-kubernetes.md) | You want to operate Bifröst in an existing cluster. | Persistent volumes, enforced NetworkPolicy and a configured access flow. |

See the [distribution matrices](distribution.md#compatibility) for platform and edition support. Installing Bifröst in a container or Pod does not automatically grant access to host accounts or permission to create session containers or Pods.

If you're still not sure that to pick, maybe our [Use-Cases](../usecases.md) will help you.

## Installation

Different guides, for the different ways how to operate Bifröst:

1. [On Host](on-host.md)
2. [In Docker/Container](in-docker.md)
3. [In Kubernetes with Helm](in-kubernetes.md)

## What's next?

Read [Use-Cases](../usecases.md) and [the configuration documentation](../reference/configuration.md) to see what you can do more with Bifröst.
