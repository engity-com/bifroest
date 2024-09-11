---
description: How environments within Bifröst work where the users sessions are executed.
---

# Environments

Bifröst executes user sessions within environments. These environments can either be the [local environment](local.md) of the host (where Bifröst runs on) itself or even containers (currently in development [Docker](https://github.com/engity-com/bifroest/issues/11) and [Kubernetes](https://github.com/engity-com/bifroest/issues/12)).

## Types

1. `local`: [Local](local.md)

## Examples

1. Using [local environment on Linux](local.md#linux):
   ```yaml
   type: local
   name: "{{.authorization.user.name}}"
   ```
2. Using [local environment on Windows](local.md#windows):
   ```yaml
   type: local
   ```
