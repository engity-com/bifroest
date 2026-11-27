# Bifröst Helm chart

Run Bifröst in an existing Kubernetes cluster. The [installation guide](https://bifroest.engity.org/setup/in-kubernetes/) walks through credentials, configuration, installation and a first SSH login.

Requires Kubernetes 1.32 or newer with Linux nodes, persistent volumes, enforced NetworkPolicy and Helm 4.3.2. Helm 3 is not supported.

## Install

Prepare `values.yaml` with your access flow using the guide. The default flow denies every login. Replace `<version>` with the full release version without its leading `v`:

```shell
helm upgrade --install bifroest oci://ghcr.io/engity-com/bifroest --version <version> --namespace bifroest --create-namespace -f values.yaml --wait --timeout 5m
```

The default image matches the chart's application version. SSH uses a private ClusterIP Service; HTTP ingress is disabled. Each Pod has its own persistent volume, retained on scale-down and uninstall.

## Configuration and operation

* [Configuration sources and deployment settings](https://bifroest.engity.org/setup/in-kubernetes/#configuration-sources)
* [HTTP ingress with an existing controller](https://bifroest.engity.org/setup/in-kubernetes/#http-ingress)
* [Direct TLS-ALPN-01 ACME through the HTTP Service](https://bifroest.engity.org/setup/in-kubernetes/#direct-acme)
* [TLS and rotating certificate Secrets](https://bifroest.engity.org/reference/transports/tls/)
* [Prometheus Pod scraping](https://bifroest.engity.org/guides/monitoring/#scrape-the-helm-deployment)
* [Upgrades, replicas and retained state](https://bifroest.engity.org/setup/operations/#helm-releases-and-persistent-state)

The chart does not install an ingress controller, certificate manager or permissions for Kubernetes session Pods. These are separate operator choices.
