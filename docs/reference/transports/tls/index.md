---
description: Configure server TLS with certificate files, ACME or temporary testing certificates.
---

# TLS

Configures TLS for incoming connections using certificate files, ACME or a temporary testing certificate.

A TLS definition can be shared between the [HTTP](../../connection/http/index.md#property-tls) and [monitoring](../../monitoring.md#property-tls) listeners.

## Properties

<<property("minVersion", "string", default="1.3")>>
Minimum TLS version, either `"1.2"` or `"1.3"`.

<<property("certificates", array_ref("Certificate", "#certificate"))>>
Explicit PEM certificate/key pairs. Each entry requires both file paths. Explicit material takes priority; invalid material fails startup instead of falling back to ACME.

If no certificates are supplied and neither [`dummy`](#property-dummy) nor [`acme`](#property-acme) is enabled, the following configuration is used, depending on the platform:

Linux:

```yaml
certificates:
  - certificateFile: /etc/engity/bifroest/tls/tls.crt
    privateKeyFile: /etc/engity/bifroest/tls/tls.key
```

macOS:

```yaml
certificates:
  - certificateFile: /Library/Application Support/Engity/Bifroest/tls/tls.crt
    privateKeyFile: /Library/Application Support/Engity/Bifroest/tls/tls.key
```

Windows:

```yaml
certificates:
  - certificateFile: C:\ProgramData\Engity\Bifroest\tls\tls.crt
    privateKeyFile: C:\ProgramData\Engity\Bifroest\tls\tls.key
```

<<property("dummy", "bool", default=False)>>
Generate an ephemeral self-signed certificate for the consumer's configured names. Expires after 24 hours; a restart creates a new key and certificate. Cannot be combined with certificate files or ACME.

!!! warning
    Dummy TLS is for testing only. Clients do not trust it; use trusted certificates or ACME for production.

<<property("reloadInterval", "Duration", "../../data-type.md#duration", default="5s")>>
File reload interval. `0s` selects the default; negative values are invalid. A complete valid generation replaces live material atomically. Invalid updates retain previous valid material; expired certificates cannot accept new handshakes. Established connections remain open.

<<property("acme", "ACME", "#acme", optional=True)>>
Obtain and renew certificates for configured names not covered by explicit certificates. Omit `acme` or set it to `null` to disable ACME; a mapping enables it and requires `acceptTerms: true`.

## Certificate

Each entry in `certificates` has these properties.

<<property("certificateFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="certificate-", heading=3)>>
Local PEM certificate-chain file covering the consumer's names, including IP SANs when connecting by IP.

<<property("privateKeyFile", "File Path", "../../data-type.md#file-path", required=True, id_prefix="certificate-", heading=3)>>
Local PEM private-key file, separate from SSH, audit and other signing identities, public assets and mutable repositories.

On Unix, use service-owned keys with owner-only permissions. Root-managed, read-only files for the service's primary group are also accepted, for example a Kubernetes Secret with `defaultMode: 0440` and `fsGroup: 10001`; do not grant other users access. Mount Secrets as read-only directories without `subPath` so generation changes remain visible.

## ACME

ACME uses **TLS-ALPN-01 only**. Every requested DNS name must resolve to an address whose public TCP **443** reaches Bifröst. [The protocol fixes this public port](https://www.rfc-editor.org/rfc/rfc8737#section-3); a load balancer may forward it to a different local port, such as 8443.

Validation uses [`http.addresses`](../../connection/http/index.md#property-addresses). An HTTP listener with TLS must be enabled; use [`http.enabled: acmeTlsAlpnOnly`](../../connection/http/index.md#property-enabled) for validation without HTTP application endpoints. A regular HTTP Ingress cannot forward TLS-ALPN-01.

After startup, [housekeeping](../../housekeeping.md#property-every) checks for due renewals at its configured interval. Certificate-file reloads use `reloadInterval` independently.

These properties belong to `acme` in either an inline or a named TLS definition.

<<property("acceptTerms", "bool", default=False, id_prefix="acme-", heading=3)>>
Accept the certificate authority's terms of service. Must be `true` when ACME is enabled. For the default directory, see [Let's Encrypt's terms](https://letsencrypt.org/repository/).

<<property("email", "string", default="", id_prefix="acme-", heading=3)>>
Optional contact email address, without a display name.

<<property("directoryUrl", "URL", "../../data-type.md#url", default="https://acme-v02.api.letsencrypt.org/directory", id_prefix="acme-", heading=3)>>
Certificate authority's HTTPS directory URL, without credentials, query or fragment. A staging service can be used for testing; its certificates are not browser-trusted.

<<property("storage", "File Path", "../../data-type.md#file-path", default="<os specific>", id_prefix="acme-", heading=3)>>
Persistent private directory for ACME account and certificate keys. Preserve it across restarts and keep it separate from public assets and other service storage.

The default value is different, depending on the platform Bifröst runs on:

* Linux: `/var/lib/engity/bifroest/tls/<name>/acme`
* macOS: `/Library/Application Support/Engity/Bifroest/tls/<name>/acme`
* Windows: `C:\ProgramData\Engity\Bifroest\tls\<name>\acme`

`<name>` is the name in the root `tls` map. Inline TLS uses `http/acme` or `monitoring/acme` instead of `tls/<name>/acme`, under the same platform-specific base directory.

Preserve an existing account's explicit storage path when reorganizing definitions. Independent TLS sources must not write the same store or claim the same active ACME name. Direct automation is intended for one instance; use externally renewed certificate files for multiple replicas.

## Examples

Add these settings to a configuration with existing flows.

### Inline TLS

```yaml
http:
  enabled: true
  domains: [bifroest.example.org]
  tls:
    acme:
      acceptTerms: true
      email: operator@example.org
```

### Referenced TLS

The same definition can be named and referenced. Naming it `default` also lets HTTP select it when `http.tls` is omitted or `""`:

```yaml
tls:
  public:
    acme:
      acceptTerms: true
      email: operator@example.org
http:
  enabled: true
  domains: [bifroest.example.org]
  tls: public
```

### Temporary testing certificate

Dummy TLS works in both inline and named definitions:

```yaml
tls:
  testing:
    dummy: true
http:
  enabled: true
  domains: [localhost]
  tls: testing
```

### Shared certificate files

HTTP and private monitoring use different domains with shared certificate files covering both:

```yaml
tls:
  shared:
    certificates:
      - certificateFile: /run/bifroest/tls/tls.crt
        privateKeyFile: /run/bifroest/tls/tls.key
http:
  enabled: true
  domains: [bifroest.example.org]
  tls: shared
monitoring:
  enabled: true
  addresses: ["localhost:9090"]
  domains: [monitoring.example.org]
  tls: shared
```

### ACME without HTTP browser access

Obtain a certificate for private monitoring without starting HTTP application endpoints. Forward public TCP 443 to local port 8443; keep monitoring private.

```yaml
http:
  enabled: acmeTlsAlpnOnly
  addresses: [":8443"]
  domains: [monitoring.example.org]
  tls: monitoring
tls:
  monitoring:
    acme:
      acceptTerms: true
      email: operator@example.org
monitoring:
  enabled: true
  addresses: ["localhost:9090"]
  domains: [monitoring.example.org]
  tls: monitoring
```

## Compatibility

| <<dist("linux")>> | <<dist("darwin")>> | <<dist("windows")>> |
| - | - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"darwin")>> | <<compatibility_editions(True,None,"windows")>> |
