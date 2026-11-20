---
description: Connect to Bifröst over HTTPS or WSS using OpenSSH and curl, without a separate tunnel client.
---

# SSH over HTTPS with OpenSSH and curl

Use your regular SSH client to reach Bifröst through HTTPS instead of a direct SSH port. SSH authentication, host-key verification, SFTP and forwarding policies remain unchanged.

## Prerequisites

* Bifröst has [HTTPS and its SSH tunnel enabled](../reference/connection/http/index.md#ssh-tunnel), with a trusted certificate and an SSH-eligible flow. A direct SSH listener and the WebUI are not required.
* You have the flow's normal SSH credentials and the verified Bifröst SSH host-key fingerprint.
* Your workstation has OpenSSH and a [suitable curl build](../reference/connection/http/index.md#curl-transport-capabilities).

## Configure OpenSSH

Add this to `~/.ssh/config` (`%USERPROFILE%\.ssh\config` on Windows), replacing `HostName` and `User` with your server and SSH login name:

```sshconfig
Host bifroest-https
    HostName bifroest.example.org
    User alice
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ProxyCommand curl -q -fsSN --no-progress-meter --http1.1 -T . -X POST -H "Expect:" -H "Content-Type: application/octet-stream" https://%h/api/v1/ssh
```

OpenSSH replaces `%h` with `HostName`. On Windows, use `curl.exe` instead of `curl`. Quote executable and file paths containing spaces.

For a private CA, add `--cacert "/path/to/ca.pem"` to `ProxyCommand` before the URL; do not disable certificate verification.

## Connect

```sh
ssh bifroest-https
```

Verify the SSH host key against the fingerprint provided by your administrator, then authenticate as usual. HTTPS certificate verification does not replace this SSH host-key check. The configured flow opens through the HTTPS tunnel; the keepalive settings keep idle connections active.

For file transfers, use the same configuration:

```sh
sftp bifroest-https
```

SFTP and port forwarding are available only when the selected environment and authorization allow them.

## Use WSS instead

Use a curl build with working WSS duplex support and replace only `ProxyCommand`:

```sshconfig
    ProxyCommand curl -q -fsSN --no-progress-meter --http1.1 -T . -X GET -H "Expect:" wss://%h/api/v1/ssh
```

!!! warning
    Windows curl 8.22.0/Schannel fails simultaneous WSS send/receive and can cause SSH integrity failures. Use the HTTPS/1.1 example above with that build.

## Next steps

* [SSH gateway to an OpenSSH server](ssh-gateway.md) routes authenticated sessions to a private SSH target.
* [OIDC login](oidc.md) adds identity-provider authentication to SSH connections.
* [HTTP connection reference](../reference/connection/http/index.md#ssh-tunnel) covers tunnel switches, TLS configuration and curl compatibility.
