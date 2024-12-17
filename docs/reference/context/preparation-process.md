---
description: How to access context information of a Preparation Process of Bifröst.
---

# Context Preparation Process

Holds the information about a [Preparation Process](../connection/ssh.md#preparationMessages) of Bifröst.

## Properties

<<property("id", "string")>>

Each preparation process has its own unique ID (like [`pull-image`](../environment/docker.md#preparationProcess-pull-image) of the [docker environment](../environment/docker.md)).

For information about process types, see the documentation for the supported [environments](../environment/index.md).

<<property("flow", "string")>>

Holds the [name of flow](../flow.md#property-name) which context holds this preparation process.

<<property("progress", "float32", optional=True)>>

In case of update events, this holds the current progress of the whole process in `0.0` to `1.0`.

<<property("percentage", "float32", optional=True)>>

Same as [`progress`](#property-progress) but multiplied with `100.0` to be able to be used directly as percentage value. Therefore, the value can be `0.0` to `100.0`.

<<property("error", "any", optional=True)>>

In case of error events, this holds the full error information.

!!! danger
     Should usually not be displayed to end-users because it can contain sensitive system information which should only be exposed inside of log files.

     This property should only be used for evaluation what should be displayed instead of displaying itself.

<<property("*", "any", optional=True)>>

Each preparation process can provide other information, like [`image` in case of a docker `pull-image` process](../environment/docker.md#preparationProcess-pull-image-property-image).

For information about process types, see the documentation for the supported [environments](../environment/index.md).
