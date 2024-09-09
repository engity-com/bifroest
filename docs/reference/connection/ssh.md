---
description: Defines the whole behavior of the SSH protocol by itself for a user who is connecting to Bifröst.
---
# SSH connection

Defines the whole behavior of the SSH protocol by itself for a user who is connecting to Bifröst.

## Configuration

<<property_with_holder("addresses", "Array", None, "Net Address", "../data-type.md#net-address", default=[":22"])>>
To which address the service will bind and listen to.
``
<<property("keys", "Keys", "#keys")>>
See [below](#keys).

<<property("idleTimeout", "Duration", "../data-type.md#duration", default="10m")>>
For how long a connection can be idle before it will forcibly be closed. The client can send keep alive packages to extend the idle time. `0` means that the connection will never time out.

<<property("maxTimeout", "Duration", "../data-type.md#duration", default=0)>>
The maximum duration a connection can be connected before it will be forcibly be closed, regardless if there are actions or not. `0` means that the connection will never time out.

<<property("maxAuthTries", "uint8", None, default=6)>>
How much different authentication methods a client can use before the connection will be rejected.

<<property("maxConnections", "uint8", None, default=255)>>
The maximum amount of parallel connections on this service. Each new connecting connection will be rejected.

<<property_with_holder("banner", "String Template", "../templating/index.md#string", "Connection", "../context/connection.md", default='{{ `/etc/ssh/sshd-banner` | file `optional` | default `Transcend with Engity Bifröst\n\n` }}')>>
Banner which will be shown if the client connects to the server before the first even the validation of authorizations or similar happens.

## Examples

```yaml
addresses: [ ":22" ]
keys:
  hostKeys: [ /etc/engity/bifroest/key ]
  # ...
idleTimeout: 10m
maxTimeout: 0
maxAuthTries: 6
maxConnections: 255
banner: "Yeah!"
```

## Keys

### Configuration

<<property_with_holder("hostKeys", "Array", None, "File Path", "../data-type.md#file-path", default=['<defaultLocation>'], heading=4)>>
Where to store the host keys at. If they do not exist, they will be created as Ed25519 key.

Default Locations:

* Linux: `/etc/engity/bifroest/key`
* Windows: `C:\ProgramData\Engity\Bifroest\key`

<<property("rsaRestriction", "RSA Restriction", "../data-type.md#rsa-restriction", default="at-least-4096-bits", heading=4)>>
Restrict which RSA keys are allowed to be used.

<<property("dsaRestriction", "DSA Restriction", "../data-type.md#dsa-restriction", default="none", heading=4)>>
Restrict which DSA keys are allowed to be used.

<<property("ecdsaRestriction", "ECDSA Restriction", "../data-type.md#ecdsa-restriction", default="at-least-384-bits", heading=4)>>
Restrict which ECDSA keys are allowed to be used.

<<property("ed25519Restriction", "ED25519 Restriction", "../data-type.md#ed25519-restriction", default="all", heading= 4)>>
Restrict which ED25519 keys are allowed to be used.

<<property_with_holder("rememberMeNotification", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", default="If you return until {{.session.validUntil | format `dateTimeT`}} with the same public key ({{.key | fingerprint}}), you can seamlessly log in again.\n\n", heading=4)>>

Banner which will be shown if the connection was based on an authentication method (like OIDC) which does not have its own public key authentication. At this point the authentication was successful AND the client submitted at least one public key (as authentication try). This key will be used and this message will be shown to the client to inform, that this key will be used for the session from now on. As a result the original authentication will be skipped (like OIDC) as long it is not expired and the client presents the same public key.

### Examples

```yaml
hostKeys: [ /etc/engity/bifroest/key ]
rsaRestriction: at-least-4096-bits
dsaRestriction: none
ecdsaRestriction: at-least-384-bits
ed25519Restriction: all
rememberMeNotification: "If you return until {{.session.validUntil | format `dateTimeT`}} with the same public key {{.key | fingerprint}}), you can seamlessly login again.\n\n"
```

## Compatibility

| [`linux`/`generic`](../../setup/distribution.md#linux-generic) | [`linux`/`extended`](../../setup/distribution.md#linux-extended) | [`windows`/`generic`](../../setup/distribution.md#windows-generic) |
| - | - | - |
| <<compatibility(True)>> | <<compatibility(True)>> | <<compatibility(True)>> |