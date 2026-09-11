---
description: Connect a Bifröst flow to another SSH server.
toc_depth: 5
---

# SSH environment

The SSH environment terminates the incoming SSH connection at Bifröst and creates a separately authenticated SSH connection to a target server. All sessions and direct TCP forwarding channels of one incoming connection share one target SSH transport.

Each target transport allows up to 64 concurrently active or pending shell, SFTP, forwarding and agent channels. Additional locally requested channels wait for capacity; excess agent channels initiated by the target are rejected.

## Configuration {: #configuration}

<<property("type", "Environment Type", default="ssh", required=True)>>
Has to be set to `ssh` to enable the SSH environment.

<<property("variables", "Environment Variables", "../data-type.md#environment-variables", template_context="../context/authorization.md")>>
Defines environment variables sent to the target for commands, shells and SFTP. They override values received from the SSH client, `authorized_keys` and authorization. Bifröst-generated runtime variables take precedence. Variables are sent as best-effort SSH `env` requests; the target server decides which variables it accepts, commonly through OpenSSH `AcceptEnv`.

<<property("address", "string", template_context="../context/authorization.md", required=True)>>
Target SSH address. The port defaults to `22`. DNS names, IPv4 addresses and IPv6 addresses can omit it; an explicit IPv6 port uses `[address]:port` form.

<<property("user", "string", template_context="../context/authorization.md", required=True)>>
User used to authenticate at the target SSH server.

<<property("os", "Os", "../data-type.md#os", default="linux")>>
Operating system of the target. This controls case-sensitive or case-insensitive environment-variable precedence.

<<property("knownHosts", "string")>>
Inline OpenSSH `known_hosts` content. A YAML block string can contain multiple entries.

<<property("knownHostsFile", "string")>>
Explicit path to one OpenSSH `known_hosts` file. Bifröst never implicitly reads user or system `known_hosts` files. `knownHosts` and `knownHostsFile` can be used together.

<<property("acceptAllHostKeys", "bool", default=False)>>
Disables target host-key verification. This cannot be combined with `knownHosts` or `knownHostsFile` and should only be used in controlled test environments.

!!! danger
     Setting `acceptAllHostKeys: true` makes the target connection vulnerable to on-path attacks.

<<property("identityFiles", "list of strings", template_context="../context/authorization.md")>>
Private SSH keys offered to the target. Every configured file has to exist and contain an unencrypted private key. If the list is absent or empty, Bifröst offers all configured server host keys as client identities. An invalid explicit entry never activates this fallback.

`identityFiles` and `certificate` are mutually exclusive. If neither is configured, the server-host-key fallback remains active.

<<property("certificate", "SSH User Certificate", "#certificate")>>
Enables a persistent OpenSSH user certificate for the target connection. See [below](#certificate).

<<property("connectTimeout", "duration", template_context="../context/authorization.md", default="10s")>>
Maximum duration for TCP connection establishment and SSH handshake. `0` disables this timeout.

<<property("loginAllowed", "bool", template_context="../context/authorization.md", default=True)>>
Controls whether the environment accepts an authorization.

<<property("banner", "string", template_context="../context/authorization.md", default="")>>
Displayed before an interactive target shell is opened.

<<property("portForwardingAllowed", "bool", template_context="../context/authorization.md", default=True)>>
Controls local and dynamic forwarding after the applicable authorized-key policy has also been checked. Reverse forwarding is not supported by the SSH environment.

At least one host-key verification source is required unless `acceptAllHostKeys` is explicitly enabled.

## SSH User Certificate {: #certificate}

Bifröst issues exactly one certificate for each persistent Bifröst session. Reconnecting and restarting Bifröst reuse the byte-identical certificate until its immutable validity boundary is reached.

### Configuration {: #certificate-configuration}

<<property("identityFile", "File Path", "../data-type.md#file-path", id_prefix="certificate-", heading=4)>>
Static path to the private subject key used with the certificate. The default is `/etc/engity/bifroest/client-key` on Unix and `C:\ProgramData\Engity\Bifroest\client-key` on Windows. The default key is shared by all certificate-enabled flows of one Bifröst instance. If the file does not exist, an Ed25519 key is generated. Existing unreadable, encrypted or invalid files cause startup to fail and are never overwritten. The private key is not copied into session storage.

<<property("authorityIdentityFile", "File Path", "../data-type.md#file-path", id_prefix="certificate-", heading=4)>>
Static path to the private SSH certificate-authority key. The default is `/etc/engity/bifroest/ca` on Unix and `C:\ProgramData\Engity\Bifroest\ca` on Windows. The default CA is shared by all certificate-enabled flows of one Bifröst instance. If the file does not exist, an Ed25519 key is generated. Existing unreadable, encrypted or invalid files cause startup to fail and are never overwritten. The server host key is never used as certificate authority. Existing certificates remain bound to their original CA after a configured CA rotation.

Bifröst does not create a `.pub` companion file for either private key. The CA public key is logged at every startup and can be exported for a specific flow with `bifroest key export ca`.

<<property("validity", "duration", default="15m", id_prefix="certificate-", heading=4)>>
Positive lifetime of a newly issued certificate. The first issuance persists `MaxValidUntil`, and reconnects, activity and later configuration increases never move that boundary. This lifetime is separate from the dynamic Bifröst session idle timeout.

Certificate expiry does not disconnect an already authenticated downstream SSH transport, the incoming client connection or the Bifröst session. It only prevents the expired certificate from authenticating a new or re-established downstream SSH connection. Connection and session timeouts control their respective lifetimes independently.

<<property("validAfterSkew", "duration", default="30s", id_prefix="certificate-", heading=4)>>
Non-negative clock skew subtracted from the issuance time for the OpenSSH `ValidAfter` field.

<<property("audience", "string", template_context="../context/authorization.md", id_prefix="certificate-", heading=4)>>
Enables the Bifröst delegation profile and identifies the intended downstream authorization, normally its flow name. If absent, the certificate uses the interoperable audit profile. The two profiles are described [below](#certificate-profiles).

<<property("principals", "list of strings", template_context="../context/authorization.md", id_prefix="certificate-", heading=4)>>
Additional OpenSSH principals. The rendered target `user` is always included and empty rendered principals are rejected.

<<property("extensions", "map of strings", template_context="../context/authorization.md", id_prefix="certificate-", heading=4)>>
OpenSSH certificate extensions and their values. Standard extensions such as `permit-pty`, `permit-port-forwarding` and `permit-agent-forwarding` are removed when the effective incoming authorization policy denies the corresponding capability. Names ending in `@bifroest.engity.org` are reserved for Bifröst metadata.

Certificate metadata uses only the reserved `evidence-v1@bifroest.engity.org` extension. The size-limited evidence document contains allowlisted origin, hop, target and capability fields; passwords, OAuth tokens and unrestricted authorization data are never included.

### Certificate profiles {: #certificate-profiles}

Without `audience`, Bifröst issues an audit-profile certificate. Its evidence is a non-critical extension, so standard OpenSSH and Bifröst's `simple` and `local` authorizations can authenticate it while ignoring the metadata.

With `audience`, Bifröst additionally sets the critical option `bifroest-delegation@bifroest.engity.org`. Standard OpenSSH and authorization types that do not understand this option reject the certificate. Only [`authorization.type: bifroest`](../authorization/bifroest.md) validates the signed evidence and accepts the delegation.

When a `bifroest` authorization forwards to another SSH environment, the original identity and validated hop history are retained. The new hop cannot move `ValidAfter` earlier, extend `ValidBefore`, or restore a PTY, port-forwarding or agent-forwarding capability denied upstream. Because destination-specific `permitopen` and `permitlisten` rules are hop-local, their presence conservatively disables delegated port forwarding rather than broadening it downstream.

## Supported operations

| Operation | Behavior |
| --- | --- |
| Shell and exec | Opened as separate channels on the shared target transport |
| stdin, stdout and stderr | Forwarded without merging stderr into stdout |
| Exit status | Returned from the target command |
| PTY and resize | Terminal type, modes, dimensions and later window changes are forwarded |
| Signals | Forwarded to the target session |
| SFTP | The target `sftp` subsystem is streamed directly |
| SCP | Modern SCP uses SFTP; legacy SCP is handled as an exec command |
| Agent forwarding | Forwarded only when requested and permitted by the authorization policy |
| `ssh -L` and `ssh -D` | Connections originate from the target SSH server's network |
| `ssh -R` | Rejected; reverse forwarding is not supported by the SSH environment |

Arbitrary subsystems and SSH break requests are not forwarded.

!!! warning
     OpenSSH agent forwarding is scoped to an SSH connection rather than an individual session. After one permitted session enables forwarding, the target can access that source agent until the incoming SSH connection ends. Only enable agent forwarding for trusted targets.

## Examples

### Private key authentication

```yaml
type: ssh
address: target.example.org
user: '{{ .session.created.remote.user }}'
knownHosts: |
  target.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
identityFiles:
  - /etc/engity/bifroest/id_target
variables:
  LC_ALL: C.UTF-8
```

### OpenSSH certificate authentication

1. Import the running OpenSSH server's host key, then use this flow:
    ```shell
    bifroest key import host \
      --knownHostsFile /etc/engity/bifroest/known_hosts \
      --address internal.example.org \
      --expectedFingerprint SHA256:...
    ```

    !!! warning
         A plain password and `--expectedFingerprint unknown` are suitable only for testing. Verify production host-key fingerprints independently and use a password hash or another authorization.

2. Configure Bifröst:
    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    flows:
      - name: openssh
        authorization:
          type: simple
          entries:
            - name: alice
              password: plain:change-me
        environment:
          type: ssh
          address: internal.example.org
          user: alice
          knownHostsFile: /etc/engity/bifroest/known_hosts
          certificate:
            extensions:
              permit-pty: ""
    ```

    !!! note
         The OpenSSH server needs a local `alice` account. Leave `audience` unset because OpenSSH does not understand Bifröst's delegation critical option.

3. Export the CA and deploy the output as `/etc/ssh/bifroest-ca.pub` on the OpenSSH server:
    ```shell
    bifroest key export ca \
      -c /etc/engity/bifroest/configuration.yaml \
      openssh \
      --output /tmp/ca.pub
    ```

4. Configure `sshd`:
    ```text title="/etc/ssh/sshd_config.d/bifroest.conf"
    PubkeyAuthentication yes
    TrustedUserCAKeys /etc/ssh/bifroest-ca.pub
    ```

5. Restart `sshd`:
    ```shell
    systemctl restart sshd
    ```

### Bifröst delegation

For Bifröst-to-Bifröst certificate delegation, see the [Bifröst authorization example](../authorization/bifroest.md#example-entry-gateway-to-target-gateway).

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
