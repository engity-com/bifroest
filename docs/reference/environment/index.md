---
description: How environments within Bifröst work when user sessions are executed.
---

# Environments

Bifröst executes user sessions within environments. These environments can either be the [local environment](local.md) of the host (on which Bifröst runs on) itself or even containers.

Configure an environment inline in a [flow](../flow.md#property-environment), or
define it once in the root [`environments` map](../configuration.md#property-environments)
and reference its map key. The map value contains `type` and the same settings
shown below. Omitted, `null` or empty flow values use `environments.default` only
if explicitly defined; otherwise an environment is required.

## Types

1. `docker`: [Docker](docker.md) executes each user session inside a separate Docker container.
2. `kubernetes`: [Kubernetes](kubernetes.md) executes each user session inside a separate POD in a defined cluster.
3. `local`: [Local](local.md) executes on the host itself (same host on which Bifröst is running).
4. `ssh`: [SSH](ssh.md) connects to another SSH server and forwards sessions and direct TCP channels.
5. `dummy`: [Dummy](dummy.md) for demonstration purposes, it simply prints a message and exists immediately.
6. `management`: [Management](management.md) provides authorized structured administrative commands via SSH and HTTP without a shell.

## Shared SSH and browser execution

Local, Docker, Kubernetes, SSH and Dummy environments support browser terminals.
They share session quotas, authorization restrictions, audit logging and recording
with SSH. Each new terminal starts a fresh execution, not a reattachment.
Agent forwarding, SFTP and other named subsystems remain SSH-only.

Configured environment banners are shell text: with a PTY, bare LF line breaks
are sent as CRLF so SSH and browser terminals both start the next line at column
zero. Existing CRLF, standalone carriage returns and other bytes are preserved.
Without a PTY the banner stays byte-exact. This does not enable a global terminal
conversion: backend process output, exec/subsystem streams and existing
recordings are not rewritten.

Management uses a separate structured browser view, not a host shell or CLI
subprocess. See [Browser access](../../guides/browser-access.md) for operation
and the [security limits](../connection/http/security.md) for restrictions.

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
6. Using an [SSH environment](ssh.md):
   ```yaml
   type: ssh
   address: target.example.org
   user: service-user
   knownHostsFile: /etc/engity/bifroest/known_hosts
   identityFiles:
     - /etc/engity/bifroest/id_target
   ```
7. Using [dummy environment](dummy.md) with a simple message:
   ```yaml
   type: dummy
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```
