---
description: How environments within Bifröst work when user sessions are executed.
---

# Environments

Bifröst executes user sessions within environments. These environments can either be the [local environment](local.md) of the host (on which Bifröst runs on) itself or even containers.

## Types

1. `docker`: [Docker](docker.md) executes each user session inside a separate Docker container.
2. `kubernetes`: [Kubernetes](kubernetes.md) executes each user session inside a separate POD in a defined cluster.
3. `local`: [Local](local.md) executes on the host itself (same host on which Bifröst is running).
4. `dummy`: [Dummy](dummy.md) for demonstration purposes, it simply prints a message and exists immediately.

## Examples

1. Using [local environment](local.md):
   ```yaml
   type: local
   name: "{{.authorization.user.name}}"
   ```
2. Using simple [kubernetes environment](kubernetes.md):
   ```yaml
   type: kubernetes
   ```
3. Using simple [docker environment](docker.md):
   ```yaml
   type: docker
   ```
4. Using [kubernetes environment](kubernetes.md) with Ubuntu image, custom kubeconfig file and additional settings:
   ```yaml
   type: kubernetes
   config: "/etc/kube/my-kube-config"
   context: "my-kube-context"
   image: ubuntu
   ## Using /bin/bash instead of /bin/sh,
   ## because it does exist in the image
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
5. Using [docker environment](docker.md) with Ubuntu image and additional settings:
   ```yaml
   type: docker
   image: ubuntu
   ## Using /bin/bash instead of /bin/sh,
   ## because it does exist in the image
   shellCommand: [/bin/bash]
   execCommand: [/bin/bash, -c]
   ```
6. Using [dummy environment](dummy.md) with a simple message:
   ```yaml
   type: dummy
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```
