---
description: Defines the behavior of the SSH protocol for a user who is connecting to Bifröst.
---
# SSH connection

Defines the behavior of the SSH protocol for a user who is connecting to Bifröst.

## Configuration

<<property("addresses", array_ref("Net Address", "../data-type.md#net-address"), default=[":22"])>>
To which address the service will bind and listen to.

<<property("keys", "Keys", "#keys")>>
See [below](#keys).

<<property("messages", "Messages", "#messages")>>
See [below](#messages).

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="10m")>>
For how long a connection can be idle before it will forcibly be closed. The client can send keep-alive packets to extend the idle time. `0` disables this timeout.

<<property("maxTimeout", "Duration", "../data-type.md#duration", default=0)>>
The maximum duration a connection can be open before it will forcibly be closed, regardless of whether it is active. `0` disables this timeout.

<<property("gracefulShutdownTimeout", "Duration", "../data-type.md#duration", default="30s")>>
How long Bifröst waits for active SSH connections and their handlers to finish after shutdown starts and the listeners have been closed. Remaining connections are forcibly closed when this single time budget expires. Shared resources remain open until their handlers have finished cleanup. `0` disables waiting and closes connections immediately.

<<property("handshakeTimeout", "Duration", "../data-type.md#duration", default="2m")>>
The maximum duration from accepting a connection until successful SSH authentication. `0` disables this timeout.

<<property("sessionRequestTimeout", "Duration", "../data-type.md#duration", default="30s")>>
How long an accepted session channel may wait for its initial shell, exec, or subsystem request. `0` disables this timeout.

<<property("maxAuthTries", "uint8", None, default=6)>>
How many authentication attempts a client can make before the connection is rejected. `0` disables this limit.

<<property("maxConnections", "uint32", None, default=255)>>
The maximum number of parallel connections on this service. Every additional connection is rejected.

<<property("maxStartupsStart", "uint16", None, default=10)>>
The number of concurrent unauthenticated connections accepted before random early dropping starts. `0` starts the early-drop calculation with the first unauthenticated connection. This setting has no effect when `maxStartupsFull` is `0`.

<<property("maxStartupsRate", "uint8", None, default=30)>>
The initial probability, in percent, of dropping a new unauthenticated connection after `maxStartupsStart` is reached. It must be between `0` and `100`; the probability increases toward `100` as `maxStartupsFull` is approached.

<<property("maxStartupsFull", "uint16", None, default=100)>>
The hard limit for concurrent unauthenticated connections per SSH listener. When greater than `0`, it must be greater than or equal to `maxStartupsStart`. `0` disables the complete pre-authentication connection limit.

<<property("maxSessionsPerConnection", "uint16", None, default=10)>>
The maximum number of active SSH session channels per connection. `0` disables this limit.

<<property("maxChannelsPerConnection", "uint16", None, default=64)>>
The maximum number of active SSH channels of all supported types per connection. `0` disables this limit.

<<property("maxReverseForwardsPerConnection", "uint16", None, default=16)>>
The maximum number of active reverse-forward listeners per connection. `0` disables this limit.

<<property("maxChannels", "uint16", None, default=64)>>
The maximum number of active SSH channels across all connections handled by one SSH listener. `0` disables this limit.

<<property("maxReverseForwards", "uint16", None, default=256)>>
The maximum number of active reverse-forward listeners across all connections handled by one SSH listener. `0` disables this limit.

<<property("proxyProtocol", "bool", None, default=false)>>
If enabled, Bifröst supports incoming connections using [PROXY protocol versions 1 and 2](https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address).
Only enable this when the SSH listener is exclusively reachable through trusted proxies. The current boolean configuration trusts the source addresses supplied by every peer that can reach the listener.

OpenSSH Unix-socket forwarding (`direct-streamlocal@openssh.com` and `streamlocal-forward@openssh.com`) is not enabled. Bifröst currently has no cross-environment policy for socket paths, ownership, permissions, and cleanup.

<<property("banner", "string", template_context="../context/connection.md", default='{{ `/etc/ssh/sshd-banner` | file `optional` | default `Transcend with Engity\'s Bifröst\n\n` }}')>>
Banner which will be shown when the client connects to the server even before the first validation of authorizations or similar happens.

<<property("preparationMessages", "Preparation Messages", "#preparationMessages")>>
See [below](#preparationMessages).

## Examples

```yaml
addresses: [ ":22" ]
keys:
  hostKeys: [ /etc/engity/bifroest/key ]
  # ...
messages:
  # ...
idleTimeout: 10m
maxTimeout: 0
gracefulShutdownTimeout: 30s
handshakeTimeout: 2m
sessionRequestTimeout: 30s
maxAuthTries: 6
maxConnections: 255
maxStartupsStart: 10
maxStartupsRate: 30
maxStartupsFull: 100
maxSessionsPerConnection: 10
maxChannelsPerConnection: 64
maxReverseForwardsPerConnection: 16
maxChannels: 64
maxReverseForwards: 256
proxyProtocol: false
banner: "Yeah!"
```

## Keys

### Configuration {: #keys-configuration }

<<property("hostKeys", array_ref("File Path", "../data-type.md#file-path"), default=['<defaultLocation>'], heading=4, id_prefix="keys-")>>
Where to store the host keys at. If they do not exist, they will be created as Ed25519 key.

Default Locations:

* Linux: `/etc/engity/bifroest/key`
* Windows: `C:\ProgramData\Engity\Bifroest\key`

<<property("exchanges", "Exchanges", "../data-type.md#ssh-key-exchange", default=["curve25519-sha256@libssh.org", "curve25519-sha256", "diffie-hellman-group16-sha512", "mlkem768x25519-sha256"], heading=4, id_prefix="keys-")>>
Restrict which key exchanges are allowed to be used.

<<property("rsaRestriction", "RSA Restriction", "../data-type.md#rsa-restriction", default="at-least-4096-bits", heading=4, id_prefix="keys-")>>
Restrict which RSA keys are allowed to be used.

<<property("dsaRestriction", "DSA Restriction", "../data-type.md#dsa-restriction", default="none", heading=4, id_prefix="keys-")>>
Restrict which DSA keys are allowed to be used.

<<property("ecdsaRestriction", "ECDSA Restriction", "../data-type.md#ecdsa-restriction", default="at-least-384-bits", heading=4, id_prefix="keys-")>>
Restrict which ECDSA keys are allowed to be used.

<<property("ed25519Restriction", "ED25519 Restriction", "../data-type.md#ed25519-restriction", default="all", heading= 4, id_prefix="keys-")>>
Restrict which ED25519 keys are allowed to be used.

<<property("rememberMeNotification", "string", template_context="../context/authorization.md", default="If you return until {{.session.validUntil | format `dateTimeT`}} with the same public key ({{.key | fingerprint}}), you can seamlessly log in again.\n\n", heading=4, id_prefix="keys-")>>

Banner which will be shown if the connection was based on an authentication method (like OIDC) which does not have its own public key authentication. At this point, the authentication was successful AND the client submitted at least one public key (as authentication try). This key will be used and this message will be shown to the client to inform that this key will be used for the session from now on. As a result, the original authentication will be skipped (like OIDC) as long as it is not expired and the client presents the same public key.

### Examples {: #keys-examples }

```yaml
hostKeys: [ /etc/engity/bifroest/key ]
exchanges:
  - curve25519-sha256@libssh.org
  - curve25519-sha256
  - diffie-hellman-group16-sha512
  - mlkem768x25519-sha256
rsaRestriction: at-least-4096-bits
dsaRestriction: none
ecdsaRestriction: at-least-384-bits
ed25519Restriction: all
rememberMeNotification: "If you return until {{.session.validUntil | format `dateTimeT`}} with the same public key {{.key | fingerprint}}), you can seamlessly login again.\n\n"
```

## Messages

### Configuration {: #messages-configuration }

<<property("authentications", "Authentications", "../data-type.md#ssh-message-authentication", default=["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"], heading=4, id_prefix="messages-")>>
Restrict which message authentications are allowed to be used.

<<property("ciphers", "Ciphers", "../data-type.md#ssh-ciphers", default=["aes256-gcm@openssh.com", "aes256-ctr", "aes192-ctr"], heading=4, id_prefix="messages-")>>
Restrict which ciphers are allowed to be used.

### Examples {: #messages-examples }

```yaml
authentications:
  - hmac-sha2-512-etm@openssh.com
  - hmac-sha2-256-etm@openssh.com
ciphers:
  - aes256-gcm@openssh.com
  - aes256-ctr
  - aes192-ctr
```

## Preparation Messages {: #preparationMessages }

In some cases the connection will not be available instantly. For example if the [docker environment](../environment/docker.md) is used and an image needs to be downloaded first, this could take some seconds. In these cases different parts of Bifröst might trigger these messages being displayed. By default, all of them are displayed as described [below](#preparationMessages-configuration).

As this is an array of preparation messages, the first which matches, wins.

### Configuration {: #preparationMessages-configuration }

<<property("id", "Regex", "../data-type.md#regex", default=".*", heading=4, id_prefix="preparationMessages-")>>
Each preparation proces has a unique ID (like [`pull-image`](../environment/docker.md#preparationProcess-pull-image) of the [docker environment](../environment/docker.md)).

This property defines a [regular expression](../data-type.md#regex) this ID has to match together with [`flow`](#preparationMessages-property-flow).

<<property("flow", "Regex", "../data-type.md#regex", default=".*", heading=4, id_prefix="preparationMessages-")>>
Each preparation process will be produces by a [flow](../flow.md).

This property defines a [regular expression](../data-type.md#regex) the [name of this flow](../flow.md#property-name) has to match together with [`id`](#preparationMessages-property-id).

<<property("start", "string", template_context="../context/preparation-process.md", default="{{.title}}...", heading=4, id_prefix="preparationMessages-")>>
This message is shown when a preparation process starts.

<<property("update", "string", template_context="../context/preparation-process.md", default="\r{{.title}}... {{.percentage | printf `%.0f%%`}}", heading=4, id_prefix="preparationMessages-")>>
This message is shown on each status change of a preparation process.

<<property("end", "string", template_context="../context/preparation-process.md", default="\r{{.title}}... DONE!\n", heading=4, id_prefix="preparationMessages-")>>
This message is shown if the preparation process finishes successful.

<<property("error", "string", template_context="../context/preparation-process.md", default="\r{{.title}}... FAILED! Contact server operator for more information. Disconnecting now...\n", heading=4, id_prefix="preparationMessages-")>>
This message is shown if the preparation process finishes with an error. The direct consequence will be that the connection will be closed by Bifröst immediately.

### Examples {: #preparationMessages-examples }

```yaml title="Show special message for pull-image process (all flows), but default for the rest"
preparationMessages:
  - id: ^pull-image$
    # {{.image}} is NOT part of the common set of properties of
    # a Preparation Message it is specific to this message.
    # Please visit the details of each Preparation Message type
    # for details.
    start: "Going to download image {{.image}}..."
    update: "\rGoing to download image {{.image}}... {{.percentage | printf `%.0f%%`}}"
    end: "\rImage {{.image}} downloaded.\n"
    error: "\rFailed to download image {{.image}}.\n"
  - {} # Entry with all default values as mentioned above
```

```yaml title="Disable messages completely, for all preparation processes"
preparationMessages:
  - start: ""
    update: ""
    end: ""
    error: ""
```

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
