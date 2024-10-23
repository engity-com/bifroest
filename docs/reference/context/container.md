---
description: How to access context information about a Docker/OCI container within Bifröst.
---

# Context Container

Represents a Docker/OCI container.

## Properties

<<property("id", "string")>>

The given ID of the container.

<<property("image", "string")>>

The actual image of the container.

<<property("name", "string", optional=True)>>

The given name of the container.

<<property("flow", "Flow Name", "../data-type.md#flow-name", optional=True)>>

The flow this container is connected to. It can be absent if this container isn't and never was connected to any flow.
