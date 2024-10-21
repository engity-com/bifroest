---
description: How to get started with Bifröst? How to install, configure and run it.
toc_depth: 2
---

# Getting started

Bifröst is available as a binary for many different platforms, or even as an OCI/Docker image.

Before we get started, you need to choose your operating mode. Here are the main differences to help you decide:

| Criteria | [On Host](on-host.md) | [In Docker/Container](in-docker.md) |
| -------- | ------ | ---------------- |
| Available features | :fontawesome-solid-circle-plus: All ([depending on used edition](distribution.md)) | :fontawesome-solid-circle-plus: All ([depending on used edition](distribution.md)) |
| [Compatibility (os/architecture)](distribution.md#compatibility) | :fontawesome-solid-circle-plus: Available for the most amount of different platforms. | :fontawesome-regular-circle: Available for the major platforms. |
| Consumption (CPU/RAM/storage)| :fontawesome-solid-circle-plus: Lowest possible consumption. | :fontawesome-regular-circle: Meaningful overhead, caused virtualization and additional processes. |
| Host integration | :fontawesome-solid-circle-plus: It runs directly on the host and has therefore direct access to everything on the host. | :fontawesome-solid-circle-plus: If running in [privileged mode](../reference/environment/docker.md#property-privileged) and all required devices are mounted, same as _On host_. |
| Host isolation | :fontawesome-solid-circle-minus: Possible, but complicated and designed for it. | :fontawesome-solid-circle-plus: Maximum possible, by design. |
| Interactions with containers | :fontawesome-regular-circle: Full, [except if interacting with Docker for Desktop](../reference/environment/docker.md#property-impPublishHost). | :fontawesome-solid-circle-plus: Full |
| Installation effort | :fontawesome-solid-circle-plus: Minimal | :fontawesome-solid-circle-plus: Minimal |

If you're still not sure that to pick, maybe our [Use-Cases](../usecases.md) will help you.

## Installation

Different guides, for the different ways how to operate Bifröst:

1. [On Host](on-host.md)
2. [In Docker/Container](in-docker.md)

## What's next?

Read [Use-Cases](../usecases.md) and [the configuration documentation](../reference/configuration.md) to see what you can do more with Bifröst.
