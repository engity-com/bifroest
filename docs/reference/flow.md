---
toc_depth: 6
description: Define how users authenticate and which environment their session uses.
---

# Flows

A flow combines an [authorization](authorization/index.md) with an
[environment](environment/index.md). Different flows can serve different users,
hosts or browser access links.

Flows are tried in configuration order:

1. Is the incoming transport enabled for this flow?
2. Does the request meet its [requirements](#requirement)?
3. Does authorization succeed?
4. Can the request use the configured environment and a compatible session?

A denied authorization can try the next flow; an authorization error stops the
attempt. A published HTTP link selects exactly one flow and never falls through
to another flow if access is denied.

## Configuration

<<property("name", "Flow Name", "data-type.md#flow-name", required=True)>>
Unique flow name, used in logs and stored [sessions](session/index.md).

!!! warning
    Changing a flow's name breaks its existing sessions.

<<property("auditlog", "Audit log Name", "auditlog/index.md", default="default")>>
Name of the audit log used by this flow. It must exist in the root
`auditlog` list. Omitting that list provides a disabled entry named `default`.

<<property("ssh", "SSH transport", "#ssh-transport")>>
Controls incoming SSH access, independently of HTTP.

<<property("http", "HTTP transport", "#http-transport")>>
Controls browser access, the requesting-name prompt and terminal keepalive.

!!! note
    Enabling the [root HTTP endpoint](connection/http.md) makes every flow
    HTTP-eligible by default. Set `http.enabled: false` on flows that should
    remain SSH-only.

<<property("discoverAsSlug", "string", default="")>>
Publishes an HTTP access link for this flow on its allowed hosts. An empty value
publishes nothing. Only HTTP-enabled flows publish links.

A slug has one or two case-sensitive alphanumeric segments, each 1–64 characters
long. For example, `servers/Example` publishes `/servers/Example`. Leading or
trailing slashes, empty segments and URL-encoded aliases are not allowed.

The link still requires authorization and all configured requirements. Two flows
cannot publish the same slug on the same configured domain. Disjoint domains
may use the same slug.

<<property("requirement", "Requirement", "#requirement")>>
Rules a request must satisfy before authorization.

<<property("authorization", "Authorization", "authorization/index.md", required=True)>>
Defines how the user authenticates and which access is permitted.

<<property("environment", "Environment", "environment/index.md", required=True)>>
Defines where the authorized user's session runs.

### SSH transport

<<property("enabled", "bool", default=True, id_prefix="ssh-", heading=4)>>
Accepts incoming SSH authentication for this flow. `false` does not disable HTTP
or SSH used to connect to a downstream target.

### HTTP transport

<<property("enabled", "bool", default=True, id_prefix="http-", heading=4)>>
Allows HTTP authentication and discovery for this flow. The root HTTP endpoint
must also be enabled. `false` leaves SSH unchanged.

<<property("requestUser", "bool", default=True, id_prefix="http-", heading=4)>>
Asks the browser user for a requesting name. With `false`, the browser sends an
empty name. This is useful for OIDC flows that identify users through the IdP.
Methods needing a name cannot guess one instead.

Name requirements still apply: `^sso$` does not match an empty name; `^$` does.
The requesting name is not the verified
[principal](context/authentication.md#property-principal) or the target account.

<<property("keepAlive", "string", template_context="context/authorization.md", default="15s", id_prefix="http-", heading=4)>>
Keepalive interval for browser terminals, from `1s` to `5m`. A user may change
it in **Connection settings**. Prefix the value with `!` to prevent changes.
Quote values starting with `!` in YAML.

The template is evaluated after authentication using the current session context.
An enforced value overrides saved browser preferences. Keepalive preserves only
the network connection; it does not extend session or RememberMe timeouts.

```yaml title="Editable interval"
http:
  keepAlive: 10s
```

```yaml title="Enforced interval based on the authenticated user"
http:
  keepAlive: '{{ if eq .authentication.principal "alice" }}10s{{ else }}!20s{{ end }}'
```

## Requirement

Requirements are checked before authorization. General name rules apply to SSH
and HTTP. Transport-specific rules apply **in addition**: all applicable rules
must match.

### Configuration {: #requirement-configuration }

<<property("includedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-", heading=4)>>
Include rule for the requesting name, such as `alice` in `ssh alice@host`.
Empty means unrestricted.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-", heading=4)>>
Exclude rule for the requesting name. Empty excludes nothing.

!!! note
    Regular expressions match substrings unless anchored. Use `^alice$` to
    match the complete name, rather than also matching `alice-admin`.

### SSH requirements

These properties belong to `requirement.ssh`.

<<property("includedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-ssh-", heading=4)>>
Additional include rule for the SSH requesting name. Empty means unrestricted.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-ssh-", heading=4)>>
Additional exclude rule for the SSH requesting name. Empty excludes nothing.

### HTTP requirements

These properties belong to `requirement.http`.

<<property("includedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Additional include rule for the HTTP requesting name, which may be empty.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Additional exclude rule for the HTTP requesting name.

<<property("includedHost", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Include rule for the canonical host: lowercase, without port or trailing DNS
dot. For example, `APP.EXAMPLE.:443` becomes `app.example`. IPv6 literals keep
their brackets.

<<property("excludedHost", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Exclude rule for the canonical host.

<<property("includedSlug", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Include rule for the slug without a leading slash. The root has slug `""`.

<<property("excludedSlug", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
Exclude rule for the slug.

Empty include rules do not restrict access; empty exclude rules exclude nothing.
Host rules only narrow the endpoint's [domain list](connection/http.md#property-domains).
Discovery links do not bypass these requirements.

## Examples

### Different SSH login names

```yaml
flows:
  - name: sso
    requirement:
      includedRequestingName: ^sso$
    authorization:
      type: oidcDeviceAuth
      # ...
    environment:
      type: local
      # ...

  - name: local
    authorization:
      type: local
      # ...
    environment:
      type: local
      # ...
```

### A browser-only OIDC link

This flow publishes `https://app.example.org/servers/Example` without asking for
a login name. Configure the [HTTPS endpoint](connection/http.md) separately.
The IdP must support device authorization and, by default, refresh tokens.
Its verified principal must map to an allowed local account; configure the
[principal mapping](authorization/index.md#principal-mapping) accordingly.

```yaml
flows:
  - name: browser
    ssh:
      enabled: false
    http:
      requestUser: false
    discoverAsSlug: servers/Example
    requirement:
      includedRequestingName: '^$'
      http:
        includedHost: '^app\.example\.org$'
        includedSlug: '^servers/Example$'
    authorization:
      type: oidcDeviceAuth
      issuer: https://identity.example.org
      clientId: bifroest
      clientSecret: example-only
    environment:
      type: local
      name: '{{ .authentication.principal }}'
```

## Next topics

* [Configuration](configuration.md)
* [Environments](environment/index.md)
* [Authorizations](authorization/index.md)
