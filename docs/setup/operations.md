---
description: Operate Bifröst behind a load balancer or reverse proxy, manage instance-local state and plan restarts or recovery.
---

# Operations and availability

For the configuration and delivery workflow, see the [concept](../concept.md).

* **Who operates it?** You run the [host service](on-host.md), [container](in-docker.md) or [Helm deployment](in-kubernetes.md), supply configuration and keys, and maintain the identity provider and workload dependencies. [Management](../reference/environment/management.md) acts on that instance; it does not provide fleet-wide or tenant-scoped administration.
* **What survives a restart?** With durable storage, [sessions and saved-access registrations](../reference/session/fs.md) can survive. Preserve keys and complete evidence repositories too; use the [checklist below](#restart-and-recovery-checklist).
* **What happens if an instance fails?** Reconnect to the same Bifröst endpoint and sign in on a healthy instance to continue working with the workload data available there. **Bifröst sessions are not shared between instances**; reconnecting starts a new execution, not the previous shell.[^instances]
* **Is HA built in?** Not built in, but you can provide HA access by running independent instances behind a TCP load balancer such as [HAProxy](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/protocol-support/tcp/) or [NGINX stream](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html). Prefer sticky sessions and a redundant load-balancer endpoint.

## Choose a deployment {: #high-availability-current-limits }

| Deployment | What to plan |
| --- | --- |
| One supervised instance | Durable storage, backups and a tested restart. Existing connections are interrupted. |
| Independent instances behind a TCP load balancer | Sticky sessions for normal operation; health checks route reconnecting clients to a healthy instance. Use separate repositories and [audit signing identities](../reference/auditlog/index.md#property-identityFile), and make required workload data reachable from each instance. |
| Independent instances behind an HTTP ingress | Explicit [reverse-proxy mode](../reference/connection/http/index.md#upstream), protected backend access, controlled forwarded headers and HTTP affinity. Native SSH needs separate routing. |
| Replacement using an instance's existing state | Coordinate exclusive repository and workload ownership. Test recovery on your actual storage and infrastructure. |

**Keep repositories instance-local.** Each repository has one writer.[^writer] When replacing an instance using its existing state, prevent the old writer from accessing that state or its workloads first. Local locks are not cross-host fencing; never delete a lock file to force a second writer to start.

## Routing and probes

* **Prepare the shared endpoint.** Configure [SSH host keys trusted by your clients](../reference/connection/ssh.md#keys). Choose [TLS passthrough](../reference/connection/http/index.md#tls) with certificates on every backend, or [explicit reverse-proxy mode](../reference/connection/http/index.md#upstream) with public TLS at the ingress. For subpaths, configure prefix stripping and forwarded headers. Keep the backend private; in Kubernetes, use an enforced NetworkPolicy allowing only the intended ingress sources.
* **Prefer sticky sessions.** Keep [browser requests and SSH-initiated OIDC approvals](../reference/connection/http/index.md#load-balancers-and-instance-routing) on the same instance during normal operation. Configure TCP persistence through [HAProxy stick tables](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/custom-rules/stick-tables/) or [NGINX upstream hashing](https://nginx.org/en/docs/stream/ngx_stream_upstream_module.html#hash).
* **Monitor each instance.** Use [readiness checks](../guides/monitoring.md#configure-kubernetes-probes) to take unavailable backends out of rotation. `/ready` reports new-access readiness, `/status` process liveness; also test an actual login.

HTTP cookie affinity can keep browser requests on one instance, but does not tie a native SSH connection to a browser on another device. Use tested cross-transport routing, such as instance-specific OIDC endpoints. Kubernetes `ClientIP` affinity is not a general solution under NAT or when ingress routes directly to Pods.

## Helm releases and persistent state

The [Helm chart](in-kubernetes.md) runs a StatefulSet with one persistent volume per Pod. Sessions, host keys and configured evidence repositories belong to that Pod, not to a shared cluster-wide session store. Keep writable state under `/var/lib/engity/bifroest` and back up complete repositories and their keys using the [restart checklist](#restart-and-recovery-checklist).

### Update configuration or upgrade

Read the [upgrade notes](upgrade.md), back up state and allow for interrupted connections. Keep all your values files; replace `<version>` with the full target release, without its leading `v`:

```sh
helm upgrade bifroest oci://ghcr.io/engity-com/bifroest --version <version> --namespace bifroest -f values.yaml --wait --timeout 5m
kubectl --namespace bifroest rollout status statefulset/bifroest-bifroest
```

Inline configuration changes trigger a Pod rollout through Helm. After changing configuration in an external Secret or ConfigMap, explicitly restart the Pods:

```sh
kubectl --namespace bifroest rollout restart statefulset/bifroest-bifroest
kubectl --namespace bifroest rollout status statefulset/bifroest-bifroest
```

Test an actual login after readiness succeeds. Replacing Pods interrupts their connections; neither Helm rollback nor a retained PVC restores running shells. External HTTP certificates can [reload without a rollout](#rotate-external-http-certificates) when mounted as directories rather than `subPath` files.

Choose storage class, access mode and initial claim size before installing. Changing the StatefulSet's claim template is not a normal Helm upgrade; plan storage migration or expansion using your provisioner's supported procedure. Do not delete PVCs to make an upgrade succeed.

### Add replicas

Increase `replicaCount` in your Helm values only after configuring a consistently trusted SSH identity and testing [related-connection routing](#routing-and-probes). Each ordinal gets a separate PVC; there is no shared `existingClaim`. Place replicas across suitable nodes if you need node-failure tolerance. An optional disruption budget must leave at least one replica available for voluntary disruption:

```yaml title="Additional Helm values"
replicaCount: 2
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

This does not replicate sessions or move existing shells. When several instances create Kubernetes session Pods, also review their [cleanup ownership](../reference/environment/kubernetes.md#property-cleanOrphan).

### Remove or reinstall

`helm uninstall bifroest --namespace bifroest` stops the deployment but retains its PVCs. Scale-down also retains them. Reinstalling with the same release name, namespace and StatefulSet name can reuse that state. Keep these names stable and prevent any previous writer from running before reusing its volume. Delete PVCs or the namespace only when you deliberately want to remove the stored state and have the required backups.

## Rotate external HTTP certificates

1. Provision a valid [certificate/key pair](../reference/connection/http/index.md#certificate), with private-key ownership and permissions suitable for the service account.
2. Publish both files as one generation, preserving their configured paths. Projected Secret or Certbot symlink changes are supported; Kubernetes `subPath` mounts do not update automatically.
3. Allow the configured [reload interval](../reference/connection/http/index.md#tls-property-reloadInterval), check logs and test a new TLS connection. Existing connections remain open. A rejected rotation keeps the previous valid material, not a certificate past its expiry.

This reload applies to the application HTTP listener, not the separate monitoring listener. With TLS termination at the ingress and backend TLS disabled, rotate the ingress certificate through its own certificate manager.

## Restart or recover one instance {: #restart-and-recovery-checklist }

In a load-balanced deployment, take only the affected instance out of rotation; healthy instances can keep accepting connections. Keep an independent administration path and define acceptable recovery time and data loss.

1. **Block new traffic to this instance and stop its writer.** Let users finish or [disconnect their connections](../reference/cli/session/disconnect.md). Allow the configured [SSH](../reference/connection/ssh.md#property-gracefulShutdownTimeout) and [HTTP](../reference/connection/http/index.md#property-gracefulShutdownTimeout) shutdown budgets. A failed readiness probe is not proof that the old process has stopped.
2. **Copy or restore complete state while stopped:** [configuration](../reference/configuration.md) and referenced keys, [sessions](../reference/session/fs.md#property-storage), [journals and signing identities](../reference/auditlog/index.md#journal), [Recording repositories](../reference/auditlog/recording.md#storage-and-recovery) and [ACME storage](../reference/connection/http/index.md#acme-property-storage). Protect backups as credentials; back up workload data separately and keep decryption private keys offline. Remote sealed artifacts alone are not a service backup.
3. **Check identities and revocations.** Retain the matching host and signing keys. An older session backup can restore later-revoked saved access: reconcile it before reopening traffic. Perform [upgrades](upgrade.md) separately from the first recovery attempt.
4. **Start one writer for the recovered state** through its existing [host service manager](on-host.md), [container supervisor](in-docker.md) or [Helm deployment](#helm-releases-and-persistent-state), initially with the same release and configuration. Inspect startup logs and [check readiness directly](../guides/monitoring.md#scrape-a-host-locally); keep this instance out of rotation during acceptance checks. Resolve key or integrity errors instead of discarding repositories.
5. **Test before reopening:**
    * Test workload access over each enabled transport: [SSH](on-host.md), [SSH over HTTPS](../guides/ssh-over-https.md) and/or [browser](../guides/browser-access.md#open-your-first-shell). Then test eligible [saved access](../usecases.md#remembered-access). Old browser access and pending logins must be rejected; a reusable session must reach the intended environment, not restore an old shell.
    * [Verify retained evidence](../reference/cli/verification.md#trust-a-producer) against independent producer trust and check [remote delivery](../reference/auditlog/remote-targets/index.md#delivery-behavior), if configured.
    * Test [revocation](../usecases.md#offboard) and [cleanup](../reference/housekeeping.md#cleanup-guarantees). Record recovery time and data gaps against your objectives, then return this instance to the pool.

**Result:** the recovered instance accepts new logins again. With healthy backends available, users can reconnect and continue working while the affected instance recovers; existing shells remain tied to their original instance.

[^writer]: <<asset_link("pkg/session/fs-lock_test.go", "Process-lock and crash-reopen tests")>> cover local filesystem ownership and recovery.
[^instances]: <<asset_link("pkg/service/instance-boundaries_test.go", "Instance-boundary tests")>> and <<asset_link("pkg/service/http-remember_test.go", "saved-access restart tests")>> cover local-service isolation and resumption after restart.
