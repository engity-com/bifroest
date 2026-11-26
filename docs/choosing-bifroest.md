---
title: Bifröst vs OpenSSH, Warpgate and Teleport
description: Choose an access workflow with direct SSH, SSH over HTTPS, browser access, RememberMe, configurable session environments and verifiable evidence; compare Bifröst with OpenSSH, Warpgate and Teleport.
---

# Choosing Bifröst for SSH and browser access

Bifröst combines **who may connect** with **where their session runs** in configurable [flows](reference/flow.md). Users can connect through direct SSH, [SSH over HTTPS/WSS](guides/ssh-over-https.md), or the optional [browser interface](guides/browser-access.md). Optional [RememberMe](reference/data-type.md#rememberme) reduces repeated login prompts. Choose the access workflow, session environment and lifetime policy your team needs.

## Where Bifröst fits

### Client access and sign-in

* **OpenSSH when direct SSH is unavailable:** Use [OpenSSH and curl over HTTPS or WSS](guides/ssh-over-https.md) where your network permits that transport. No Bifröst-specific tunnel client, direct SSH listener or WebUI login is required. Normal SSH authentication, host-key checks, SFTP and forwarding policies still apply.
* **Browser shells and management:** Enable [HTTPS browser access](guides/browser-access.md) when users cannot install an SSH client. Terminal flows open shells; authorized management flows can inspect sessions and disconnect or dispose of them. Direct SSH does not require HTTPS, and an SSH tunnel does not require the browser interface.
* **OIDC access with standard clients:** Use [Authorization Code with PKCE or Device Authorization](guides/oidc.md) through SSH or the WebUI. Code Flow requires Bifröst HTTPS, but workload flows can remain SSH-only.
* **Reconnect without repeating every login:** [RememberMe](reference/data-type.md#rememberme) lets supported authorizations remember an SSH key or browser after successful login, reducing repeated password/MFA or IdP prompts. Access checks, revocation and session lifetimes still apply; it does not restore the previous shell.

### Session environments

* **Host access with existing accounts:** Run sessions as local users on Linux, Windows or macOS. Start with the [host installation](setup/on-host.md) and review the OpenSSH `sshd` settings you currently use.
* **A gateway to private SSH servers:** Authenticate at Bifröst, then use [separate target credentials and verified host keys](guides/ssh-gateway.md) to reach an existing OpenSSH server. Bifröst-to-Bifröst [delegation](reference/authorization/bifroest.md) is another option.
* **A workspace per session:** Start a [Docker container](reference/environment/docker.md) or [Kubernetes Pod](reference/environment/kubernetes.md) with the tools its user needs. Authenticated SSH and browser connections can reuse a compatible session and its workload, but start separate executions. Isolation depends on the privileges and mounts you grant.

### Access policy and evidence

* **Different access rules in one deployment:** Use multiple [flows](reference/flow.md) to select an authorization method and environment for different requesting usernames and policies. SSH and browser eligibility can be controlled separately.
* **Time-bound access:** By default OIDC verifies refresh grants while a session is active and closes Bifröst connections when a grant is permanently rejected. Combine this with connection and session limits for a defined [off-boarding deadline](usecases.md#offboard), such as 15 or 60 minutes; test your IdP and the complete access path.
* **Auditable access decisions:** Enable the [signed audit journal](reference/auditlog/index.md) for structured authentication and session events that you can [verify later](reference/cli/audit/verify.md).
* **Recorded terminal output:** Independently enable [session recording](guides/recording.md) when you need verifiable playback of shell and command output in the CLI or browser. Storage, retention and encryption remain operator choices.

## Concept and product boundaries

Bifröst's [concept](concept.md) combines your chosen identity source with testable YAML rules and your deployment tools — no separate management database.

Bifröst is self-hosted. Its management interface inspects and controls the connected instance; it does not edit configuration or provide tenant-scoped administration. Flows select access policies and environments, not isolated tenants. See [management operation rights](reference/environment/management.md#property-access).

For HA access, run independent instances behind a TCP load balancer, preferably with sticky sessions. If an instance fails, users reconnect to the same endpoint and sign in on a healthy instance to continue working with the workload data available there. Bifröst sessions are not shared between instances; the [operations and availability guide](setup/operations.md) explains deployment, persistence and recovery.

## Feature and workflow comparison

The cells describe the **documented workflow**, not every possible integration or an unconditional security guarantee. Features may depend on configuration, platform and edition. In Bifröst, a selected [audit logger](reference/auditlog/index.md) records access and session events; optional [session recording](reference/auditlog/recording.md) adds terminal output capture.

**Legend:** :material-check-circle: documented product workflow (configuration may still be needed); :material-tune: additional integration, client setup or edition; :material-swap-horizontal: different workflow in the cited docs; :material-help-circle-outline: not documented in the cited sources (not proof of absence); :material-minus-circle-outline: not built in. The symbols are not security ratings.

| Question | Bifröst | OpenSSH `sshd` | Warpgate | Teleport |
| --- | --- | --- | --- | --- |
| Can users connect with OpenSSH? | :material-check-circle: Directly and :material-tune: [via HTTPS/WSS with curl and client configuration](guides/ssh-over-https.md) | :material-check-circle: Directly | :material-check-circle: [Directly](https://warpgate.null.page/targets/ssh/){: rel="nofollow" } | :material-tune: [With client setup](https://goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/){: rel="nofollow" }; `tsh` is the [usual workflow](https://goteleport.com/docs/connect-your-client/teleport-clients/tsh/){: rel="nofollow" } |
| How does OIDC fit SSH login? | :material-check-circle: [Authorization Code with PKCE and SSH approval](reference/authorization/oidc/authorization-code.md), or [Device Authorization](reference/authorization/oidc/device-authorization.md); optional [RememberMe](reference/data-type.md#rememberme) for later logins | :material-tune: External integration, e.g. [PAM](https://manpages.ubuntu.com/manpages/noble/en/man5/sshd_config.5.html){: rel="nofollow" } | :material-check-circle: [Browser-based SSH login](https://warpgate.null.page/sso/){: rel="nofollow" } | :material-tune: [OIDC SSO](https://goteleport.com/docs/zero-trust-access/sso/integrate-idp/oidc/){: rel="nofollow" } in Enterprise |
| How are existing SSH targets reached? | :material-check-circle: [Separate authenticated connection](guides/ssh-gateway.md) | :material-tune: Directly, or client-side [ProxyJump](https://man.openbsd.org/ssh_config#ProxyJump){: rel="nofollow" } | :material-check-circle: [Configured SSH targets](https://warpgate.null.page/targets/ssh/){: rel="nofollow" } | :material-tune: [SSH server enrollment](https://goteleport.com/docs/enroll-resources/server-access/openssh/openssh-agentless/){: rel="nofollow" } |
| Can a session have its own Docker container or Kubernetes Pod? | :material-check-circle: [Docker container](reference/environment/docker.md) or [Pod](reference/environment/kubernetes.md); compatible sessions may be reused | :material-tune: Requires external orchestration | :material-swap-horizontal: [Kubernetes API target](https://warpgate.null.page/targets/kubernetes/){: rel="nofollow" }, not a per-SSH-session Pod in the cited workflow | :material-swap-horizontal: [Kubernetes access and Pod exec](https://goteleport.com/docs/connect-your-client/teleport-clients/){: rel="nofollow" }, a different workflow |
| What does the audit log provide? | :material-check-circle: [Signed event journal](reference/auditlog/index.md); optional encryption of confidential fields | :material-tune: [Server logs](https://man.openbsd.org/sshd_config#LogLevel){: rel="nofollow" }; independent verification needs separate tooling | :material-check-circle: [Session logs](https://warpgate.null.page/targets/ssh/#client-setup){: rel="nofollow" } and [JSON log forwarding](https://warpgate.null.page/log-forwarding/){: rel="nofollow" } | :material-check-circle: [Structured audit events](https://goteleport.com/docs/reference/deployment/monitoring/audit.md){: rel="nofollow" } |
| How is a session recorded? | :material-check-circle: [Signed terminal output](reference/auditlog/recording.md); optional encryption; CLI and browser playback | :material-tune: Separate recording tooling | :material-check-circle: [Session recording and browser playback](https://warpgate.null.page/recordings/){: rel="nofollow" } | :material-check-circle: [Playback](https://goteleport.com/docs/reference/deployment/monitoring/audit.md#recorded-sessions){: rel="nofollow" } and [optional recording encryption](https://goteleport.com/docs/enroll-resources/server-access/guides/encrypted-session-recordings.md){: rel="nofollow" } |
| Can evidence be verified against a trusted signing identity? | :material-check-circle: [Audit journal](reference/cli/audit/verify.md) and [recording](reference/cli/recording/verify.md) via CLI; browser verification of downloaded originals | :material-tune: Requires separate tooling | :material-help-circle-outline: Not described in the [recording documentation](https://warpgate.null.page/recordings/){: rel="nofollow" } | :material-help-circle-outline: Not described in the [audit and recording documentation](https://goteleport.com/docs/reference/deployment/monitoring/audit.md){: rel="nofollow" } |
| Is a web terminal part of the product? | :material-check-circle: Optional [HTTPS interface](guides/browser-access.md) for configured terminal flows | :material-minus-circle-outline: Not built in | :material-check-circle: [Yes, for SSH targets](https://warpgate.null.page/targets/ssh/#connection-setup){: rel="nofollow" } | :material-check-circle: [Yes, via the Web UI](https://goteleport.com/docs/connect-your-client/teleport-clients/web-ui/){: rel="nofollow" } |

The symbols help scan the table; the text explains each result. Warpgate and Teleport have audit logs, and Teleport can encrypt recordings. Warpgate's [documented at-rest encryption](https://warpgate.null.page/encryption/){: rel="nofollow" } covers target credentials; it does not establish encryption of audit or recording artifacts. Bifröst's optional encryption and signatures are separate: encrypted artifacts still expose some metadata, and full verification of encrypted content needs the decryption key. **Not finding a signing procedure in another project's documentation is not proof that none exists.**

Browser verification and decryption run locally, but the application code comes from the server. Use the CLI in a separately trusted environment when that independence matters. See [browser compatibility](reference/connection/http/index.md#compatibility) for download limits.

Choose Bifröst when you want standard clients, configurable session environments and policy-controlled saved access together with optional signed audit and recording artifacts. HTTPS tunneling, the WebUI and RememberMe are separate choices, not prerequisites for each other.

## When another approach is preferable

Keep **OpenSSH `sshd`** if its host-account model and [existing configuration](https://man.openbsd.org/sshd_config){: rel="nofollow" } already do the job. Consider **Warpgate** when managing configured targets through its [Admin UI](https://warpgate.null.page/targets/ssh/){: rel="nofollow" } is central to your workflow. Consider **Teleport** when you want a broader infrastructure-access platform and its client and edition model fits your team.

If every connection must repeat password/MFA authentication, leave RememberMe disabled. Saved access does not replace session lifetime limits or the [off-boarding checks](usecases.md#offboard) your organization requires.

Bifröst's SSH target is not a transparent proxy for arbitrary SSH requests. Its recordings cover terminal output, not every SSH payload. Reconnecting or reloading a browser does not restore the previous shell: authenticate again or use permitted saved access to start a new execution. Management access comes from an authorized management flow, not a separate admin role. See [Security and trust](security.md) for the operational boundaries before making a choice.

Comparison based on the linked product documentation in October 2026. Check the documentation of the **versions and editions** you are evaluating; do not treat this page as a feature guarantee for another project.
