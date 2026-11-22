---
description: Describe one test's request and the authentication results Bifröst should assume for configured flows.
---

# Input {: #input }

Input describes **the situation to test**, not what you expect to happen.
For example: someone requests `ops`, and authentication for flow `primary`
returns account `alice`. Expectations belong in [assertions](assertions.md).

Supply an `object` as the value of each [test's `input`](tests.md#property-input).
The runner does not obtain missing observations from the host or an IdP.

## Properties

<<property("request", "Request", "requests.md#request", required=True, heading=3)>>
The logical SSH or HTTP request. At least `requestingName` must be explicit.

<<property("authentication", ref("Object", "lua.md#function-object", ref("Flow Name", "../data-type.md#flow-name"), ref("Authentication assumption", "#authentication")), optional=True, heading=3)>>
An object keyed by **configured YAML flow name**, not username or test name.
Supply a result for every flow whose authentication the request needs to attempt.
Omitting a needed result is an error, not an assumed denial.

If no flow reaches authentication, no outcomes are needed; `object {}` makes
that explicit. Requirements may exclude a flow before its outcome is consulted.

## Authentication assumption {: #authentication }

Each value in `input.authentication` describes one flow's authentication
assumption with the properties below. Bifröst does not check a password or run
an OIDC exchange to obtain it.

<<property("outcome", "Authentication outcome", "data-types.md#authentication-outcome", required=True, id_prefix="authentication-", heading=3)>>
The authentication result to assume for this flow, not the expected overall
test decision.

<<property("mode", "Authentication mode", "data-types.md#authentication-mode", optional=True, id_prefix="authentication-", heading=3)>>
How to interpret the assumption. Local authentication defaults to
`post-authentication`; OIDC success requires explicit `verified-oidc`.
See [local mapping](local.md#authentication) and [OIDC data](oidc.md#oidc).

<<property("account", "string", optional=True, id_prefix="authentication-", heading=3)>>
Required for local `allow` in post-authentication mode. It names an existing
supplied [Account](local.md#account), not an account to look up on the host.
Optional in mapped-local mode, but must agree with the resolved name when
supplied. Do not supply it for OIDC.

<<property("oidc", "OIDC identity", "oidc.md#oidc", optional=True, id_prefix="authentication-", heading=3)>>
Required for an OIDC `allow` with `mode = "verified-oidc"`. Not accepted for
local authentication or with an OIDC `deny`. The identity must match the
configured flow's issuer.

## Examples

Use this object as a test's `input`:

```lua
local input = object {
  request = object { requestingName = "ops" },
  authentication = object {
    primary = object { outcome = "allow", account = "alice" },
  },
}
```

`primary` refers to `flows[].name: primary` in the YAML. `alice` is a supplied
account fact. Neither name is derived from the suite's name.

For an assumed authentication denial:

```lua
local outcomes = object {
  primary = object { outcome = "deny" },
}
```

Use `outcomes` as `input.authentication`. A denial can permit a later eligible
flow to be tried. An evaluation error stops that path instead. For published
HTTP assignments, see [flow matching](requests.md#matching-and-published-flows).
