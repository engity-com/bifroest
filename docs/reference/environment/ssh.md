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
Target address in `host:port` form. IPv6 addresses have to use `[address]:port` form.

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

<<property("certificate", "SSH User Certificate")>>
Enables a persistent OpenSSH user certificate for the target connection. Bifröst issues exactly one certificate for each persistent Bifröst session. Reconnecting and restarting Bifröst reuse the byte-identical certificate until its immutable validity boundary is reached.

<<property("certificate.identityFile", "File Path", "../data-type.md#file-path", required=True)>>
Static path to the private subject key used with the certificate. If the file does not exist when Bifröst starts, an Ed25519 key is generated. Existing unreadable, encrypted or invalid files cause startup to fail and are never overwritten. The private key is not copied into session storage.

<<property("certificate.authorityIdentityFile", "File Path", "../data-type.md#file-path")>>
Static path to the private OpenSSH user-CA key. If absent, the first configured Bifröst server host key signs new user certificates. An invalid explicit CA file never activates this fallback. Existing certificates remain bound to their original CA after a configured CA rotation.

<<property("certificate.validity", "duration", required=True)>>
Positive lifetime of a newly issued certificate. The first issuance persists `MaxValidUntil`, and reconnects, activity and later configuration increases never move that boundary. This lifetime is separate from the dynamic Bifröst session idle timeout.

<<property("certificate.validAfterSkew", "duration", default="30s")>>
Non-negative clock skew subtracted from the issuance time for the OpenSSH `ValidAfter` field.

<<property("certificate.principals", "list of strings", template_context="../context/authorization.md")>>
Additional OpenSSH principals. The rendered target `user` is always included and empty rendered principals are rejected.

<<property("certificate.extensions", "map of strings", template_context="../context/authorization.md")>>
OpenSSH certificate extensions and their values. Standard extensions such as `permit-pty`, `permit-port-forwarding` and `permit-agent-forwarding` are removed when the effective incoming authorization policy denies the corresponding capability. Names ending in `@bifroest.engity.org` are reserved for Bifröst metadata.

<<property("connectTimeout", "duration", template_context="../context/authorization.md", default="10s")>>
Maximum duration for TCP connection establishment and SSH handshake. `0` disables this timeout.

<<property("loginAllowed", "bool", template_context="../context/authorization.md", default=True)>>
Controls whether the environment accepts an authorization.

<<property("banner", "string", template_context="../context/authorization.md", default="")>>
Displayed before an interactive target shell is opened.

<<property("portForwardingAllowed", "bool", template_context="../context/authorization.md", default=True)>>
Controls local and dynamic forwarding after the applicable authorized-key policy has also been checked. Reverse forwarding is not supported by the SSH environment.

At least one host-key verification source is required unless `acceptAllHostKeys` is explicitly enabled.

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

## Example

```yaml
type: ssh
address: target.example.org:22
user: '{{ .session.created.remote.user }}'
knownHosts: |
  target.example.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
identityFiles:
  - /etc/engity/bifroest/id_target
variables:
  LC_ALL: C.UTF-8
```

## User certificate example

```yaml
type: ssh
address: target.example.org:22
user: '{{ .session.created.remote.user }}'
knownHostsFile: /etc/engity/bifroest/known_hosts
certificate:
  identityFile: /var/lib/engity/bifroest/downstream-client
  authorityIdentityFile: /etc/engity/bifroest/downstream-user-ca
  validity: 24h
  validAfterSkew: 30s
  principals:
    - '{{ .session.created.remote.user }}'
  extensions:
    permit-pty: ""
    permit-port-forwarding: ""
    permit-agent-forwarding: ""
```

The target OpenSSH server must trust the corresponding CA public key, commonly through `TrustedUserCAKeys`. Deploy a new CA public key to targets before changing `authorityIdentityFile`; keep the old public key trusted until all certificates issued by it have expired.

Certificate metadata uses the reserved extensions `session-id@bifroest.engity.org`, `original-user@bifroest.engity.org`, `original-host@bifroest.engity.org`, `authorization-kind@bifroest.engity.org` and `evidence-v1@bifroest.engity.org`. The size-limited evidence document contains only allowlisted session identity, target and capability fields; passwords, OAuth tokens and unrestricted authorization data are never included. OpenSSH ignores unknown extensions unless a target-side integration evaluates them.

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
