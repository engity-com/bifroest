---
description: How environments within Bifröst work when user sessions are executed.
---

# Environments

Bifröst executes user sessions within environments. These environments can either be the [local environment](local.md) of the host (on which Bifröst runs on) itself or even containers.

## Types

1. `docker`: [Docker](docker.md) executes each user session inside a separate Docker container.
2. `kubernetes`: [Kubernetes](kubernetes.md) executes each user session inside a separate POD in a defined cluster.
3. `local`: [Local](local.md) executes on the host itself (same host on which Bifröst is running).
4. `ssh`: [SSH](ssh.md) connects to another SSH server and forwards sessions and direct TCP channels.
5. `dummy`: [Dummy](dummy.md) for demonstration purposes, it simply prints a message and exists immediately.
6. `management`: [Management](management.md) provides authorized administrative commands via SSH without a shell.

## Transport-independent terminal groundwork

Built-in Local (Unix and Windows/ConPTY), Docker, Kubernetes, SSH-target and Dummy environments expose an optional `TerminalRunner.RunTerminal` capability. Its `TerminalTask` supplies authorized context and a `pkg/terminal.Stream`: execution-scoped stdin, stdout/stderr, input/output half-close, initial PTY settings, resize events, symbolic signals and cancellation. It does not require a source SSH session. Existing `Environment.Run(Task)` and third-party SSH environments remain compatible; the SSH adapter maps channel controls onto the same backend execution code. Agent forwarding and named SSH subsystems remain separate SSH-only capabilities. Management still uses its existing structured SSH command path, not a terminal-based web workaround.

These are trusted **post-authorization** APIs, not browser credentials or authentication endpoints. The service now runs SSH and registered neutral terminal executions through one driver for session activation, environment preparation, notices/banners, task audit, recording creation/capture/sealing and exit-status validation. Each neutral connection permits one execution, not terminal reattachment. Status delivery belongs to the transport owner, which closes its connection afterwards. A new transport must not synthesize an SSH session for an environment without the optional capability.

SSH and neutral recording wrappers share output/resize capture ordering, terminal normalization and failure state. Every resize is captured before downstream coalescing; capture failure prevents unrecorded output delivery. The SSH adapter owns and drains its control workers without closing the channel before exit-status delivery.

Neutral registration rechecks authorization, immutable session ownership/target and environment compatibility before acquiring the same filesystem session connection quota used by SSH. Its optional `ActivityInterceptor` separates real I/O/control activity from read-only validity checks; background checks cannot renew the idle timeout. Session-wide revocation closes registered SSH and neutral transports and rejects late registration. Session expiry closes access without making transport close a session-disposal operation. Shutdown cancels/drains pending neutral registrations and executions before closing repositories.

The neutral path preserves principal/target contexts, forced commands and authorized-key environment layers, checks PTY permission and rejects invalid resize dimensions or non-symbolic signals even without recording. Strict audit/capture/seal failures close the owning connection; configured best-effort behavior remains separate from invalid client input. SSH agent/subsystem acknowledgements, remembered-key notifications and protocol exit-status delivery stay in the SSH adapter. Audit and recording formats are unchanged. Neutral terminal execution rejects Management environments rather than translating web actions into shell commands.

!!! warning "Shared server execution core; no web terminal yet"
    HTTP selection/login, a WebSocket protocol and its transport-specific limits, browser permissions/RememberMe, frontend and structured browser Management actions are still missing. Valid HTTP flow paths still return 501. New service tests use verified password authorization, real filesystem session quotas and signed recording files, with neutral transports that implement no SSH session/context. They test recording/audit correlation, forced commands, PTY/resize checks, strict/best-effort failures, idle/max expiry, revocation, disconnect and shutdown. Together with existing real SSH tests, these verify the common server paths, **not** a browser or real shared Docker/Kubernetes workload. Windows/ConPTY runtime is not claimed; local Unix process tests require root and are skipped when unavailable.

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
