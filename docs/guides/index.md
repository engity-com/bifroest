---
description: Practical guides for configuration testing, SSH gateways, OIDC login, browser access, remote administration and verifiable audit and Recording evidence.
---

# Guides

Choose the task you want to accomplish:

* [SSH gateway to an OpenSSH server](ssh-gateway.md): authenticate at Bifröst, then connect to a private SSH target.
* [SSH over HTTPS with OpenSSH and curl](ssh-over-https.md): connect through HTTPS or WSS without a separate tunnel client.
* [OIDC login](oidc.md): sign in through your IdP and open a container session via SSH or the WebUI.
* [Test a configuration](testing.md): write Lua expectations for offline flow selection and target mapping, then export CI reports.
* [Browser access](browser-access.md): enable HTTPS and open a browser shell as an existing local account.
* [Manage a Bifröst host remotely](management.md): configure workload and administration flows, then inspect live state from a workstation.
* [Export server public keys remotely](keys.md): retrieve configured public SSH identities, certificate authorities and active host keys through management access.
* [Record, find and replay a session](recording.md): capture terminal output, find the sealed original and verify, play or export it.
* [Verify encrypted evidence on a workstation](evidence.md): configure encrypted audit and Recording data, pin producer trust and keep decryption local.
* [Monitor a Bifröst instance](monitoring.md): scrape Prometheus metrics and configure Kubernetes startup, readiness and liveness probes.

Choose a [host, Docker or Kubernetes installation](../setup/index.md) first, and use documentation from the **same release** as your installation. Each guide states its deployment prerequisites and requires you to provide your own identities and permissions; none replaces the [configuration reference](../reference/configuration.md).

Not sure which setup fits? See [Choosing Bifröst](../choosing-bifroest.md) and [Security and trust](../security.md).
