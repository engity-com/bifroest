---
description: Config-first access with testable rules and a simple setup.
---

# Concept

Bifröst is **config-first, testable and simple to deploy**: [configure access in YAML](reference/configuration.md), test changes and deploy with your existing tools.

## Who does what?

Identities can come from an [OIDC IdP](reference/authorization/oidc/index.md), [local user accounts](reference/authorization/local.md), or [accounts defined in YAML](reference/authorization/simple.md).

| Component | Responsibility |
| --- | --- |
| **[Identity source](reference/authorization/index.md)** | Authenticate users and supply identity information. |
| **[Git](https://git-scm.com/doc)** | Version configuration and [tests](reference/testing/suites.md). |
| **CI/CD** | Run [tests in CI](setup/github-actions.md#configuration-tests) and deploy approved configuration. |
| **Bifröst** | Enforce those [rules](reference/flow.md) and provide the configured [session environments](reference/environment/index.md). |

The [management interface](reference/environment/management.md) observes and controls running [sessions](reference/session/index.md); it does not edit account definitions or access rules.

## Workflow

**Configure → test → review → deploy**

Keep YAML and [tests](guides/testing.md) together. Use [`bifroest test`](reference/cli/test.md) to check supported flow selection, identity mapping and [SSH](reference/environment/ssh.md)/[local](reference/environment/local.md) target settings before deployment. Authentication is assumed, not performed; see the [testing scope](reference/testing/index.md#scope).

Neither Git nor CI/CD is a runtime dependency: Bifröst reads the deployed files.

## Small setup

[Binary](setup/on-host.md) or [container](setup/in-docker.md), [configuration](reference/configuration.md), [required keys](security.md#service-and-storage-permissions) and [persistent storage](setup/operations.md#restart-and-recovery-checklist) — **no separate management database**. The [Helm chart](setup/in-kubernetes.md) uses one PVC per Bifröst Pod. Other dependencies follow your chosen [authorization](reference/authorization/index.md) and [environment](reference/environment/index.md).

## More topics

* [HA and recovery](setup/operations.md)
* [Off-boarding](usecases.md#offboard)
* [Security and trust](security.md)
