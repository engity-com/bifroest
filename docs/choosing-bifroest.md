---
title: Bifröst vs OpenSSH, Warpgate and Teleport
description: Compare Bifröst with OpenSSH sshd, Warpgate and Teleport for OIDC SSH login, gateways, container sessions and recording.
---

# Choosing Bifröst for SSH access

Bifröst combines **who may connect** with **where their SSH session runs** in configurable [flows](reference/flow.md). It serves standard SSH clients and can run on a host or act as an SSH gateway. The right choice depends on the access workflow you actually need.

## Where Bifröst fits

* **Host access with existing accounts:** Run sessions as local users on Linux, Windows or macOS. Start with the [host installation](setup/on-host.md) and review the OpenSSH `sshd` settings you currently use.
* **OIDC access without a dedicated SSH client:** Users connect with OpenSSH or another SSH client and complete [Device Authorization](guides/oidc.md) in a browser. The IdP must support that flow and a suitable client configuration.
* **A gateway to private SSH servers:** Authenticate at Bifröst, then use [separate target credentials and verified host keys](guides/ssh-gateway.md) to reach an existing OpenSSH server. Bifröst-to-Bifröst [delegation](reference/authorization/bifroest.md) is another option.
* **A workspace per session:** Start a [Docker container](reference/environment/docker.md) or [Kubernetes Pod](reference/environment/kubernetes.md) with a defined image and access to the tools its user needs. Isolation depends on the privileges and mounts you grant.
* **Different access rules at one SSH entry point:** Use multiple [flows](reference/flow.md) to select an authorization method and environment for different requesting usernames and policies.
* **Time-bound access:** By default OIDC verifies refresh grants while a session is active and closes Bifröst connections when a grant is rejected. Combine this with connection and session limits for a defined [off-boarding deadline](usecases.md#offboard), such as 15 or 60 minutes; test your IdP and the complete access path.
* **Auditable access decisions:** Enable the [signed audit journal](reference/auditlog/index.md) for structured authentication and session events that you can [verify later](reference/cli/audit/verify.md).
* **Recorded terminal output:** Independently enable [session recording](guides/recording.md) when you need verifiable playback of shell and command output. Storage, retention and encryption remain operator choices.

## Feature and workflow comparison

The cells describe the **documented workflow**, not every possible integration or an unconditional security guarantee. Features may depend on configuration, platform and edition. In Bifröst, the [audit journal](reference/auditlog/index.md) records access and session events; [session recording](reference/auditlog/recording.md) captures terminal output. They are independent options: recording can run without an audit journal.

**Legend:** :material-check-circle: documented product workflow (configuration may still be needed); :material-tune: additional integration, client setup or edition; :material-swap-horizontal: different workflow in the cited docs; :material-help-circle-outline: not documented in the cited sources (not proof of absence); :material-minus-circle-outline: not built in. The symbols are not security ratings.

| Question | Bifröst | OpenSSH `sshd` | Warpgate | Teleport |
| --- | --- | --- | --- | --- |
| Can users connect with OpenSSH? | :material-check-circle: Directly | :material-check-circle: Directly | :material-check-circle: [Directly](https://warpgate.null.page/targets/ssh/){: rel="nofollow" } | :material-tune: [With client setup](https://goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/){: rel="nofollow" }; `tsh` is the [usual workflow](https://goteleport.com/docs/connect-your-client/teleport-clients/tsh/){: rel="nofollow" } |
| How does OIDC fit SSH login? | :material-check-circle: [Device Authorization](guides/oidc.md) with a browser step | :material-tune: External integration, e.g. [PAM](https://manpages.ubuntu.com/manpages/noble/en/man5/sshd_config.5.html){: rel="nofollow" } | :material-check-circle: [Browser-based SSH login](https://warpgate.null.page/sso/){: rel="nofollow" } | :material-tune: [OIDC SSO](https://goteleport.com/docs/zero-trust-access/sso/integrate-idp/oidc/){: rel="nofollow" } in Enterprise |
| How are existing SSH targets reached? | :material-check-circle: [Separate authenticated connection](guides/ssh-gateway.md) | :material-tune: Directly, or client-side [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump){: rel="nofollow" } | :material-check-circle: [Configured SSH targets](https://warpgate.null.page/targets/ssh/){: rel="nofollow" } | :material-tune: [SSH server enrollment](https://goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/){: rel="nofollow" } |
| A new Docker container or Kubernetes Pod for each SSH session? | :material-check-circle: [Docker container](reference/environment/docker.md) or [Pod](reference/environment/kubernetes.md) as session environment | :material-tune: Requires external orchestration | :material-swap-horizontal: [Kubernetes API target](https://warpgate.null.page/targets/kubernetes/){: rel="nofollow" }, not a per-SSH-session Pod in the cited workflow | :material-swap-horizontal: [Kubernetes access and Pod exec](https://goteleport.com/docs/connect-your-client/teleport-clients/){: rel="nofollow" }, a different workflow |
| What does the audit log provide? | :material-check-circle: [Signed event journal](reference/auditlog/index.md); optional encryption of confidential fields | :material-tune: [Server logs](https://man.openbsd.org/sshd_config#LogLevel){: rel="nofollow" }; independent verification needs separate tooling | :material-check-circle: [Session logs](https://warpgate.null.page/targets/ssh/#client-setup){: rel="nofollow" } and [JSON log forwarding](https://warpgate.null.page/log-forwarding/){: rel="nofollow" } | :material-check-circle: [Structured audit events](https://goteleport.com/docs/reference/deployment/monitoring/audit.md){: rel="nofollow" } |
| How is a session recorded? | :material-check-circle: [Signed shell/exec output](reference/auditlog/recording.md); optional encryption of recording content | :material-tune: Separate recording tooling | :material-check-circle: [Session recording and browser playback](https://warpgate.null.page/recordings/){: rel="nofollow" } | :material-check-circle: [Playback](https://goteleport.com/docs/reference/deployment/monitoring/audit.md#recorded-sessions){: rel="nofollow" } and [optional recording encryption](https://goteleport.com/docs/enroll-resources/server-access/guides/encrypted-session-recordings.md){: rel="nofollow" } |
| Can exported evidence be verified against a trusted signing identity? | :material-check-circle: [Audit journal](reference/cli/audit/verify.md) and [recording](reference/cli/recording/verify.md) via CLI | :material-tune: Requires separate tooling | :material-help-circle-outline: Not described in the [recording documentation](https://warpgate.null.page/recordings/){: rel="nofollow" } | :material-help-circle-outline: Not described in the [audit and recording documentation](https://goteleport.com/docs/reference/deployment/monitoring/audit.md){: rel="nofollow" } |
| Is a web terminal part of the product? | :material-minus-circle-outline: Not built in | :material-minus-circle-outline: Not built in | :material-check-circle: [Yes, for SSH targets](https://warpgate.null.page/targets/ssh/#connection-setup){: rel="nofollow" } | :material-check-circle: [Yes, via the Web UI](https://goteleport.com/docs/connect-your-client/teleport-clients/web-ui/){: rel="nofollow" } |

The symbols help scan the table; the text explains each result. Warpgate and Teleport have audit logs, and Teleport can encrypt recordings. Warpgate's [documented at-rest encryption](https://warpgate.null.page/encryption/){: rel="nofollow" } covers target credentials; it does not establish encryption of audit or recording artifacts. Bifröst's optional encryption and signatures are separate: encrypted artifacts still expose some metadata, and full verification of encrypted content needs the decryption key. **Not finding a signing procedure in another project's documentation is not proof that none exists.**

Bifröst's distinguishing combination is configurable authorization and session environments **plus independently verifiable, signed audit and recording artifacts** without a dedicated client application.

## When another approach is preferable

Keep **OpenSSH `sshd`** if its host-account model and [existing configuration](https://man.openbsd.org/sshd_config){: rel="nofollow" } already do the job. Consider **Warpgate** when its browser administration, web terminal or recording playback is central to your workflow. Consider **Teleport** when you want a broader infrastructure-access platform and its client and edition model fits your team.

Bifröst's SSH target is not a transparent proxy for arbitrary SSH requests. Its recordings cover terminal output, not every SSH payload, and it has no built-in browser player. See [Security and trust](security.md) for the operational boundaries before making a choice.

Comparison based on the linked product documentation in October 2026. Check the documentation of the **versions and editions** you are evaluating; do not treat this page as a feature guarantee for another project.
