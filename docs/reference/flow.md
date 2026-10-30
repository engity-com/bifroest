---
toc_depth: 6
description: A flow represents a flow of a user's session from the authorization to the active environment. Bifröst can have one ore more.
---
# Flows

A flow represents a flow of a user's session from the [authorization](authorization/index.md) to the active [environment](environment/index.md). Unlike the majority of the SSH servers, Bifröst cannot only interpret one flow, it can interpret *one or more*. With this approach Bifröst can do something similar like HTTP servers are implementing [Virtual hosting](https://en.wikipedia.org/wiki/Virtual_hosting) - but in this case it is based on the combination of the requesting usernames (see [requirement](#requirement)) and which [authorization](authorization/index.md) the user can fulfill.

Flows are tried in configuration order. A disabled transport or an unmet requirement skips that flow before credentials or stored sessions are considered. A denied authorization can try the next candidate; an authorization error aborts the attempt. An explicitly published HTTP slug is the exception: it selects exactly one flow and never falls through to another one.

1. Is the incoming transport enabled for this flow?
2. Is the [requirement](#requirement) fulfilled?
3. Is the user successfully [authorized](authorization/index.md), including any checks required to reuse a stored [session](session/index.md)?
4. Is the configured [environment](environment/index.md) compatible with this request and authorization?
5. Can a compatible session be reused or a new one created?

!!! note "HTTP and SSH share selection and authorization rules"
    The [root HTTP configuration](connection/http.md) starts the configured HTTPS/WebUI endpoint independently of SSH. Both transports use the shared flow, identity/target association, authorization and environment rules. Published links are discovery, not credentials. Configured incoming endpoints remain jointly startup-critical: a listener, TLS or configuration failure does not silently fall back to SSH-only operation. Browser authentication and new terminal executions retain the documented host/SNI/Origin/path and authorizer-specific eligibility boundaries.

## Configuration

<<property("name", "Flow Name", "data-type.md#flow-name", required=True)>>
:   Defines the unique name of the flow. It will be used inside logs, as references for the stored [sessions](session/index.md), ...

    !!! warning
         Changing this value afterward means to break all existing sessions.

<<property("auditlog", "Audit log Name", "auditlog/index.md", default="default")>>
:   References the named audit log used by this flow. The referenced entry must exist under the root [auditlog](auditlog/index.md#property-name) list; a missing root list provides a disabled entry named `default`.

<<property("ssh", "SSH transport", "#ssh-transport")>>
:   Controls access through the incoming SSH transport, independently of HTTP.

<<property("http", "HTTP transport", "#http-transport")>>
:   Controls HTTP eligibility and the requesting-name prompt. HTTP eligibility defaults to enabled for every flow once an HTTP endpoint is available.

<<property("discoverAsSlug", "string", default="")>>
:   Publishes an explicit link on the HTTP root page and gives this slug priority over ordinary flow matching on hosts allowed by this flow's HTTP host requirements. Only HTTP-enabled flows publish links. An empty value publishes nothing.

    The selected flow must still satisfy **all** requirements and authorization checks. Failure never falls through to another flow, even one earlier in configuration order. The same slug may be used on disjoint hosts; collisions on a configured endpoint domain are configuration errors. Name and slug requirements do not resolve such collisions.

    Slugs are case-sensitive ASCII alphanumeric segments: `[a-zA-Z0-9]{1,64}(/[a-zA-Z0-9]{1,64})?`. The root `/` has slug `""`; `/servers/Foo` has slug `servers/Foo`. Query strings and fragments are not part of the slug. Encoded path aliases, trailing slashes, empty segments, dot segments, and additional segments are rejected rather than normalized. The `/_bifroest/` namespace is reserved for internal API, WebSocket, and asset routes; it is outside the slug grammar and must never enter ordinary flow matching.

<<property("requirement", "Requirement", "#requirement")>>
:   See [Requirement](#requirement), below.

<<property("authorization", "Authorization", "authorization/index.md", required=True)>>
:   Will be evaluated to ensure the requesting user is allowed to access [the environment of this flow](#property-environment).

<<property("environment", "Environment", "environment/index.md", required=True)>>
:   Once all requirements are fulfilled and the user is successfully authorized, he will execute into this [environment](environment/index.md).

### SSH transport

<<property("enabled", "bool", default=True, id_prefix="ssh-", heading=4)>>
:   Whether this flow accepts incoming SSH authentication. `false` does not disable HTTP or affect SSH used as a downstream environment transport.

### HTTP transport

<<property("enabled", "bool", default=True, id_prefix="http-", heading=4)>>
:   Whether this flow is eligible for HTTP authentication and discovery. `false` leaves SSH unchanged.

<<property("requestUser", "bool", default=True, id_prefix="http-", heading=4)>>
:   Whether the browser asks for a requesting name. With `false`, `remote.user` must be empty. The value is not synthesized from a slug, principal, or flow name. General and HTTP name requirements still check the actual empty string: `^sso$` does not match, while `^$` does. Authorization methods needing a name cannot guess an account instead.

    Use boolean `true`/`false` for transport flags. Null blocks, null flags, quoted booleans, and unknown transport fields are rejected.

## Example

```yaml
flows:
  - name: sso
    auditlog: restricted
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

## Requirement

The requirement has to be fulfilled, even before the [authorization](#property-authorization) is evaluated. General name rules apply to both SSH and HTTP. Transport-specific rules apply **in addition**, not as replacements. All applicable rules must match (AND).

### Configuration {: id=requirement-configuration }

<<property("includedRequestingName", "Regex", "data-type.md#regex", default="\"\"", id_prefix="requirement-", heading=4)>>
If this property is set, the requesting name (`ssh <requesting name>@my-host.tld`) has to fulfill this regular expression. If empty everything will be included.

!!! warning
     Keep `^` and `$` to ensure a full match, otherwise it matches only a part of it.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default="\"\"", id_prefix="requirement-", heading=4)>>
If this property is set, the requesting name (`ssh <requesting name>@my-host.tld`) has to **NOT** fulfill this regular expression. If empty everything will be included.

!!! warning
     Keep `^` and `$` to ensure a full match, otherwise it matches only a part of it.

If no flow matches the requesting name, Bifröst rejects authentication as usual and logs `no flow matches requested user` at DEBUG level. Use [`--log.level=DEBUG`](cli/index.md#general-flags) to see this diagnostic.

### SSH requirements

Under `requirement.ssh`:

<<property("includedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-ssh-", heading=4)>>
:   Additional include rule for the SSH requesting name. Empty means unrestricted.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-ssh-", heading=4)>>
:   Additional exclude rule for the SSH requesting name. Empty excludes nothing.

### HTTP requirements

Under `requirement.http`:

<<property("includedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Additional include rule for the HTTP requesting name, which may be empty.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Additional exclude rule for the HTTP requesting name.

<<property("includedHost", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Include rule for the canonical HTTP host: lowercase IDNA ASCII, without port or a trailing DNS dot. IPv6 literals retain brackets. For example, `APP.EXAMPLE.:443` matches as `app.example`.

<<property("excludedHost", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Exclude rule for the canonical HTTP host.

<<property("includedSlug", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Include rule for the validated slug without a leading slash; the root is `""`.

<<property("excludedSlug", "Regex", "data-type.md#regex", default='""', id_prefix="requirement-http-", heading=4)>>
:   Exclude rule for that slug.

Empty include rules do not restrict access; empty exclude rules exclude nothing. Regexes match substrings unless anchored with `^` and `$`. Host rules only narrow the endpoint's configured domain allowlist; they cannot authorize arbitrary domains or ACME issuance. Discovery lists only explicitly published slugs allowed on the requested host; it does not grant authorization or bypass name/slug requirements.

### Example {: id=requirement-example }

```yaml
requirement:
  includedRequestingName: ^foo$
  excludedRequestingName: ^bar$
```

HTTP selection example (no listener is enabled by this example):

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

This name-free example requires an identity provider whose verified principal maps to an allowed local account. It does not substitute the untrusted requesting name for the authenticated identity.

## Next topics
* [Configuration](configuration.md)
* [Environments](environment/index.md)
* [Authorizations](authorization/index.md)
