---
description: How environments within Bifröst work when user sessions are executed.
---

# Environments

Bifröst executes user sessions within environments. These environments can either be the [local environment](local.md) of the host (on which Bifröst runs on) itself or even containers (currently in development [Docker](https://github.com/engity-com/bifroest/issues/11) and [Kubernetes](https://github.com/engity-com/bifroest/issues/12)).

## Types

1. `local`: [Local](local.md) executes on the host itself (same host on which Bifröst is running).
2. `docker`: [Docker](docker.md) executes each user session inside a separate Docker container.
3. `dummy`: [Dummy](dummy.md) for demonstration purposes, it simply prints a message and exists immediately.

## Examples

1. Using [local environment](local.md):
   ```yaml
   type: local
   name: "{{.authorization.user.name}}"
   ```
2. Using simple [docker environment](docker.md):
   ```yaml
   type: docker
   ```
3. Using [docker environment](docker.md) with Ubuntu image and additional settings:
   ```yaml
   type: docker
   image: ubuntu
   ## Using /bin/bash instead of /bin/sh, because it does exist in the image
   shellCommand: [/bin/bash]
   execCommand: [/bin/bash, -c]

   ## Only allow login if the OIDC's groups has "my-great-group-uuid"
   ## ...and the tid (tenant ID) is "my-great-tenant-uuid"
   loginAllowed: |
       {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
       }}
   ```
4. Using [dummy environment](dummy.md) with a simple message:
   ```yaml
   type: dummy
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```
