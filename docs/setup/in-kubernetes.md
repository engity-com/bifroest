---
description: Install Bifröst with Helm in Kubernetes and connect to an existing SSH target.
toc_depth: 3
---

# Installing in Kubernetes with Helm

Run Bifröst as a gateway in an existing cluster. This example accepts your SSH key and opens a separately authenticated shell on an existing SSH server. It does not create Kubernetes session Pods or grant Kubernetes API permissions.

## Prerequisites

| Component | Requirement |
| --- | --- |
| Kubernetes | 1.32 or newer, with Linux worker nodes |
| Helm | <<minimum_version("4.3.2", "Helm 4.3.2. Helm 3 is not supported for this chart.")>> |
| Storage | A persistent-volume provisioner and a default StorageClass, or an explicitly selected `persistence.storageClass` |
| Networking | A network plugin that enforces NetworkPolicy, and outbound access to your SSH target |
| Workstation | An OpenSSH client, plus `kubectl` and Helm configured for the intended cluster |

The available images for the **worker nodes**, not the workstation, are:

<<compatibility_matrix(os="linux", packaging="image")>>

Cells show generic/extended edition support. Your Kubernetes distribution must also support the node architecture. The chart selects the generic image by default; see [distributions](distribution.md#image) before choosing another edition.

## 1. Prepare the gateway credentials

The target needs an existing `target-user` account. Create a separate key for Bifröst on your workstation:

```sh
ssh-keygen -t ed25519 -N '' -f id_target
```

Have the target administrator add `id_target.pub` to that account's `authorized_keys` and provide a verified `known_hosts` entry for `target.example.org` through a trusted channel. Prepare these files before installing:

| File on your workstation | Purpose |
| --- | --- |
| `gateway-clients.pub` | A copy of your client's public key, such as `~/.ssh/id_ed25519.pub`; its private key stays on the client |
| `id_target` | A separate private key for Bifröst, whose public key is authorized for `target-user` on the target |
| `target_known_hosts` | The target's host key, verified through a trusted channel |

Create a namespace and store those files in a Secret:

```sh
kubectl create namespace bifroest
kubectl --namespace bifroest create secret generic bifroest-gateway --from-file=gateway-clients.pub --from-file=id_target --from-file=target_known_hosts
```

Protect access to this Secret and the local private-key file. Do not use the client's private key as `id_target`.

## 2. Configure the access flow

Save this as `values.yaml`, replacing the target address and account. The target must be reachable from Bifröst's Pod.

```yaml title="values.yaml"
persistence:
  size: 10Gi

configuration:
  flows:
    - name: gateway
      discoverAsSlug: Gateway
      requirement:
        http:
          includedSlug: '^Gateway$'
      authorization:
        type: simple
        entries:
          - name: gateway
            authorizedKeysFile: /run/bifroest/gateway/gateway-clients.pub
      environment:
        type: ssh
        address: target.example.org:22
        user: target-user
        knownHostsFile: /run/bifroest/gateway/target_known_hosts
        identityFiles:
          - /run/bifroest/gateway/id_target
        portForwardingAllowed: false

extraVolumes:
  - name: gateway
    secret:
      secretName: bifroest-gateway
      defaultMode: 0440
extraVolumeMounts:
  - name: gateway
    mountPath: /run/bifroest/gateway
    readOnly: true
```

`configuration` is the regular [Bifröst configuration](../reference/configuration.md). An object merges with the chart's defaults; `flows` replaces the default flow list. Bifröst templates such as `{{ .session.id }}` are kept literally, not evaluated by Helm. Without your own flow, the chart denies every login.

`Gateway` names this flow's optional browser access link. HTTP remains disabled until you explicitly enable it.

## 3. Install and test

Replace `<version>` in every command with the full [release version](<<release_url()>>), **without** its leading `v`, including any alpha/beta suffix. Chart and application versions match; leaving `image.tag` empty selects that application version.

```sh
helm upgrade --install bifroest oci://ghcr.io/engity-com/bifroest --version <version> --namespace bifroest -f values.yaml --wait --timeout 5m
kubectl --namespace bifroest get pods,pvc
```

Expect `bifroest-bifroest-0` to be ready and its PVC to be bound. The SSH Service is private by default. For the first test, forward it to a local port:

```sh
kubectl --namespace bifroest port-forward service/bifroest-bifroest-ssh 2222:22
```

In another terminal, export Bifröst's host key through your trusted Kubernetes connection, then connect with the client's private key:

```sh
kubectl --namespace bifroest exec bifroest-bifroest-0 -- /usr/bin/bifroest key export host --configuration=/etc/engity/bifroest/configuration.yaml --address=localhost:2222 > bifroest_known_hosts
ssh -p 2222 -i PATH_TO_YOUR_CLIENT_PRIVATE_KEY -o IdentitiesOnly=yes -o UserKnownHostsFile=bifroest_known_hosts -o StrictHostKeyChecking=yes gateway@localhost 'id -un'
```

The result should be `target-user`. The exported key belongs to Bifröst, not the target; both SSH connections are verified separately. If startup or login fails, inspect `kubectl --namespace bifroest logs bifroest-bifroest-0`; a `Pending` PVC usually needs attention to the StorageClass or provisioner.

To provide direct SSH access beyond this test, choose `service.ssh.type: LoadBalancer` or `NodePort` to suit your cluster, and restrict `networkPolicy.sshPeers` to the intended sources. An HTTP Ingress does not expose native SSH.

## Configuration sources

For a complete local configuration file instead of an object, add `--set-file configuration=configuration.yaml` to the Helm command. A YAML string in `configuration` is also supported. Both replace the complete application configuration rather than merging its fields with defaults.

To mount an existing object in the same namespace, set one of these values:

| Source | Helm value |
| --- | --- |
| Secret containing `configuration.yaml` | `configuration: "secret:bifroest-config"` |
| ConfigMap containing `configuration.yaml` | `configuration: "configMap:bifroest-config"` |

Use a Secret for configuration containing credentials. Inline configuration is also stored in a Secret. A complete external configuration must supply its flows and keep listeners and storage aligned with the chart:

| Setting in the Bifröst configuration | With default chart settings |
| --- | --- |
| `flows` | Your authorization and session-environment definitions |
| `ssh.addresses` | `[":2222"]` while the SSH Service is enabled |
| `ssh.keys.hostKeys` | Writable persistent paths, such as `["/var/lib/engity/bifroest/ssh/host"]`, or mounted existing keys |
| `session.storage` | `/var/lib/engity/bifroest/sessions` |
| `monitoring.enabled` | `true` |
| `monitoring.addresses` | `[":9090"]`, matching the chart's `monitoring.port` |
| `monitoring.allowedRemoteHosts` | Permit the actual node/probe sources; `[]` relies on cluster network restrictions |

Enable monitoring TLS only together with `monitoring.scheme: HTTPS` and the necessary certificate mounts. Keep other writable repositories and generated keys under `/var/lib/engity/bifroest`; `/etc/engity/bifroest` and the root filesystem are read-only. Changes to external configuration require a [Pod rollout](operations.md#helm-releases-and-persistent-state).

## Deployment settings

Use `helm show values oci://ghcr.io/engity-com/bifroest --version <version>` for all settings. Common choices are:

| Helm value | Default | When to change it |
| --- | --- | --- |
| `replicaCount` | `1` | After planning [instance routing and separate state](operations.md#helm-releases-and-persistent-state) |
| `persistence.size` | `10Gi` per Pod | Choose the initial capacity for sessions and configured evidence repositories; [resize storage separately](operations.md#update-configuration-or-upgrade) |
| `persistence.storageClass` | `""` (cluster default) | Select your provisioner; `"-"` requests no StorageClass |
| `persistence.accessModes` | `[ReadWriteOnce]` | Use `ReadWriteOncePod` if supported by your storage |
| `image.tag` | `""` (chart's application version) | Select an [edition tag](distribution.md#image-syntax) from the same release |
| `image.digest` | `""` | Pin the image by digest; takes precedence over `image.tag` |
| `service.ssh.type` | `ClusterIP` | Expose native SSH through your cluster's chosen service type |
| `networkPolicy.sshPeers` | All IPv4/IPv6 sources | Restrict which sources can reach the SSH port |
| `networkPolicy.httpPeers`, `networkPolicy.monitoringPeers` | `[]` (deny) | Explicitly admit the ingress controller or Prometheus |
| `resources` | `{}` | Set CPU/memory requests and limits for your workload |

The Pod runs as UID/GID `10001`, with `RuntimeDefault` seccomp, no added capabilities and no privilege escalation. Mounted credentials must be readable by that identity; the volume must support its writes. Review any flow that needs additional privileges rather than granting them to every deployment.

## Next steps

* [HTTP ingress](../reference/connection/http/index.md#kubernetes-ingress-with-helm) enables browser access and SSH over HTTPS through an existing controller.
* [Prometheus with Helm](../guides/monitoring.md#scrape-the-helm-deployment) adds Pod discovery without exposing monitoring publicly.
* [Helm releases and persistent state](operations.md#helm-releases-and-persistent-state) covers upgrades, replicas and removal.
* The [Kubernetes session environment](../reference/environment/kubernetes.md) is a separate choice that requires its own credentials and permissions; installing this chart does not enable it.
