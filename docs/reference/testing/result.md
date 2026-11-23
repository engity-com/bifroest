---
description: Properties of a calculated test result, including request, identity, authentication and target settings.
---

# Results {: #result }

`actual` is the result calculated for one test. It is not the input echoed back
and not a live session. Read it inside `verify` and compare fields with
[`t:IsEqual`](assertions.md). All fields are read-only; the decision controls
which other fields exist:

| Outcome | Available data |
| --- | --- |
| Flow/target selected | Common fields, flow, identity, authentication and target settings. |
| No flow accepted | Common fields only. |
| Local `loginAllowed` denied | Common fields, flow, identity and `stage = "local-login"`; no target or authentication result. |
| Evaluation error | A report error, not an invented Result passed to `verify`. |

Reading a field that is absent for this outcome is an error, not a `nil` return.
Choose assertions for the outcome being tested rather than probing success-only
properties after a denial.

## Properties

<<property("decision", "Decision", "data-types.md#decision", heading=3)>>
Whether the supported selection steps selected a target or denied the request.

<<property("scope", "string", heading=3)>>
Always `post-authentication/session-target`.

<<property("authenticationAssumed", "bool", heading=3)>>
Always `true`: authentication outcomes were supplied by the test.

<<property("request", "Request result", "#request", heading=3)>>
The request values used for matching, after normalization.

<<property("flow", "Flow Name", "../data-type.md#flow-name", optional=True, heading=3)>>
The selected configured flow name. Also present for local-login denial; absent
when no flow accepted the request.

<<property("identity", "Identity", "#identity", optional=True, heading=3)>>
The identity after configured principal mapping, present on selection or
local-login denial.

<<property("authentication", "Authentication result", "#authentication", optional=True, heading=3)>>
The authentication identity used on selection, before principal mapping.
This is distinct from the target account and absent on denials.

<<property("environment", "SSH target or Local target", "#targets", optional=True, heading=3)>>
Calculated target settings on selection. Unlike `t.environment`, this is not
the list of supplied account facts.

<<property("stage", "string", optional=True, heading=3)>>
`local-login` when the local `loginAllowed` rule denied. Absent otherwise.

## Request result {: #request }

The request values used for matching, after normalization. Compare this with
`t.input.request` when testing normalization. It is not a live
[Connection context](../context/connection.md). It has the following properties:

<<property("requestingName", "Requesting name", "data-types.md#requesting-name", id_prefix="request-", heading=3)>>
The requesting name, unchanged; not an authenticated principal.

<<property("transport", "Transport", "data-types.md#transport", id_prefix="request-", heading=3)>>
The effective request transport.

<<property("method", "Authentication method", "data-types.md#authentication-method", id_prefix="request-", heading=3)>>
The effective method, including the `password` default when omitted in input.

<<property("host", "Host", "../data-type.md#host", optional=True, id_prefix="request-", heading=3)>>
HTTP only: canonical host **without port**.

<<property("origin", "URL", "../data-type.md#url", optional=True, id_prefix="request-", heading=3)>>
HTTP only: canonical HTTPS origin, including a nondefault port.

<<property("slug", "Slug", "data-types.md#slug", optional=True, id_prefix="request-", heading=3)>>
HTTP only: case-sensitive slug, including `""` for the root. See
[request normalization](requests.md#canonical-result).

## Identity {: #identity }

The identity after configured principal mapping, present on selection or
local-login denial. These are the three returned data fields, not the entire
production Authentication context:

<<property("principal", "string", id_prefix="identity-", heading=3)>>
The mapped principal. It is not automatically the target account.

<<property("issuer", "string", id_prefix="identity-", heading=3)>>
The identity's authority: `local` for local accounts, or the OIDC issuer.

<<property("subject", "string", id_prefix="identity-", heading=3)>>
UID/SID as a string for local accounts, or the assumed OIDC subject. Mapping
the principal does not change issuer or subject. See the product's
[identity explanation](../context/authentication.md#principal-mapping).

## Authentication result {: #authentication }

The authentication identity used on selection, before principal mapping.
This is distinct from the target account and absent on denials. Unlike the
flow-keyed input assumptions, this object has the following properties:

<<property("mode", "Authentication mode", "data-types.md#authentication-mode", id_prefix="authentication-", heading=3)>>
The effective mode that supplied the selected identity.

<<property("account", "string", optional=True, id_prefix="authentication-", heading=3)>>
Local modes only: the canonical bound account name, before principal mapping.

<<property("remoteName", "string", optional=True, id_prefix="authentication-", heading=3)>>
Mapped-local only: the name produced by the configured `remoteName` expression.

<<property("issuer", "URL", "../data-type.md#url", optional=True, id_prefix="authentication-", heading=3)>>
OIDC only: the assumed issuer.

<<property("subject", "string", optional=True, id_prefix="authentication-", heading=3)>>
OIDC only: the assumed subject. Neither tokens nor raw claims are returned here.

## Target types {: #targets }

The selected configuration determines which shape below is returned. Values
are settings, not evidence that a target exists
or a connection/login succeeds. Forwarding settings are not a complete permission
evaluation.

### SSH target {: #ssh-target }

See [SSH environment configuration](../environment/ssh.md) for the corresponding
product settings. This shape has these properties:

<<property("type", "string", id_prefix="ssh-", heading=4)>>
Always `ssh`.

<<property("address", "Net Address", "../data-type.md#net-address", id_prefix="ssh-", heading=4)>>
Rendered and normalized address, including port, e.g. `work.example.org:22`.

<<property("user", "string", id_prefix="ssh-", heading=4)>>
Rendered target account name, e.g. `mapped-alice`.

<<property("portForwardingAllowed", "bool", id_prefix="ssh-", heading=4)>>
Rendered forwarding setting.

<<property("reversePortForwardingAllowed", "bool", id_prefix="ssh-", heading=4)>>
Rendered reverse-forwarding setting.

### Local target {: #local-target }

The [local environment](../environment/local.md) returns common settings plus
platform-specific account/group selectors. A name-based selector does not
automatically acquire the supplied account's current UID/SID. Known absence can
still produce settings for deferred provisioning; the test never provisions.
The common properties are:

<<property("type", "string", id_prefix="local-", heading=4)>>
Always `local`.

<<property("kind", "string", id_prefix="local-", heading=4)>>
`local-unix` or `local-windows`.

<<property("shellCommand", array_ref("string"), id_prefix="local-", heading=4)>>
Rendered shell command arguments.

<<property("execCommandPrefix", array_ref("string"), id_prefix="local-", heading=4)>>
Rendered command prefix arguments.

<<property("directory", "string", id_prefix="local-", heading=4)>>
Rendered working directory. The path is not opened or created by the test.

<<property("portForwardingAllowed", "bool", id_prefix="local-", heading=4)>>
Rendered forwarding setting.

<<property("account", "Unix account selector", "#unix-account", id_prefix="local-unix-", heading=4)>>
**Unix only.** Requested account settings, not a copy of Account facts. Integer
IDs are preserved. Its [properties](#unix-account) are listed with the selector
types below.

<<property("name", "string", id_prefix="local-windows-", heading=4)>>
**Windows only.** Rendered/resolved target account name.

<<property("requestedSID", "SID or empty string", "data-types.md#sid", id_prefix="local-windows-", heading=4)>>
**Windows only.** Requested SID selector. An empty string is not an assertion of
the current SID.

<<property("displayName", "string", id_prefix="local-windows-", heading=4)>>
**Windows only.** Rendered display-name setting.

<<property("skel", "string", id_prefix="local-windows-", heading=4)>>
**Windows only.** Rendered skeleton setting, not a directory copied by the test.

<<property("groups", array_ref("Windows group selector", "#windows-group"), id_prefix="local-windows-", heading=4)>>
**Windows only.** Rendered requested groups; not the current account membership list.

## Selector types

### Unix account selector {: #unix-account }

The local Unix target's `account` object has the following properties:

<<property("name", "string", id_prefix="unix-account-", heading=4)>>
Requested/resolved account name. Name precedence and UID 0 follow the product resolver.

<<property("uid", "Unix ID or null", "data-types.md#unix-id", id_prefix="unix-account-", heading=4)>>
Requested UID, or `null` when no UID was requested.

<<property("displayName", "string", id_prefix="unix-account-", heading=4)>>
Rendered display-name setting.

<<property("group", "Unix group selector", "#unix-group", id_prefix="unix-account-", heading=4)>>
Requested primary group.

<<property("groups", array_ref("Unix group selector", "#unix-group"), id_prefix="unix-account-", heading=4)>>
Requested supplementary groups.

<<property("shell", "string", id_prefix="unix-account-", heading=4)>>
Rendered shell setting.

<<property("homeDir", "string", id_prefix="unix-account-", heading=4)>>
Rendered home directory setting.

<<property("skel", "string", id_prefix="unix-account-", heading=4)>>
Rendered skeleton setting. No account or filesystem changes are performed.

### Unix group selector {: #unix-group }

Used by the local Unix account selector's `group` and `groups` properties.

<<property("name", "string", id_prefix="unix-group-", heading=4)>>
Requested group name.

<<property("gid", "Unix ID or null", "data-types.md#unix-id", id_prefix="unix-group-", heading=4)>>
Requested GID, or `null` if none was requested.

### Windows group selector {: #windows-group }

Used by the local Windows target's `groups` property.

<<property("name", "string", id_prefix="windows-group-", heading=4)>>
Requested group name.

<<property("gid", "SID or empty string", "data-types.md#sid", id_prefix="windows-group-", heading=4)>>
Requested SID-valued group identifier. The name `gid` follows the product's
Windows selector vocabulary; it is not a numeric Unix GID.

## Denial example

For an expected general denial, do not read success-only fields:

```lua
local function verify(t, actual)
  t:IsEqual("deny", actual.decision)
end
```
