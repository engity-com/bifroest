---
description: Share credential stores across flows while retaining the original requesting name and per-flow session boundaries.
---

# Login-name mapping

`simple`, `htpasswd` and `local` support `remoteName`, a template evaluated once
per authorization attempt, before credential lookup. Its default is
`{{.remote.user}}`. It receives the existing
[authorization request context](../context/authorization-request.md), not a
pre-authenticated identity. Use request fields available to the selected login
method; do not derive account names from passwords or other secrets.

For example, the SSH login name `alice@host-a` can select a flow while checking
the existing credential entry or native account `alice`:

```yaml
environments:
  default: {type: dummy}
authorizations:
  shared:
    type: simple
    remoteName: '{{regexReplaceAll "@[^@]+$" .remote.user ""}}'
    entries:
      - name: alice
        passwordFile: /etc/engity/bifroest/passwords/alice
flows:
  - name: host-a
    requirement: {includedRequestingName: '@host-a$'}
    authorization: shared
  - name: host-b
    requirement: {includedRequestingName: '@host-b$'}
    authorization: shared
```

This example demonstrates credential selection only; replace the dummy
environment with reviewed target environments. To avoid ambiguity in an SSH
client's destination parser, use `ssh -l 'alice@host-a' bifroest.example.org`.
HTTP login uses the same name mapping after its normal host/slug/flow selection.

## Regex functions

The template engine already includes Sprig's Go/RE2 regex functions:

| Template | Result for `alice@host-a` |
| --- | --- |
| `{{regexFind "^[^@]+" .remote.user}}` | `alice` |
| `{{regexReplaceAll "@[^@]+$" .remote.user ""}}` | `alice` |
| `{{regexReplaceAll "^([^@]+)@(.+)$" .remote.user "${2}/${1}"}}` | `host-a/alice` |

Replacement arguments are **pattern, input, replacement**. `${1}` addresses a
capture group. The final-suffix replacement preserves an `@` inside an account
name: `alice@example.org@host-a` becomes `alice@example.org`; the first-match
example does not. `mustRegexFind` and `mustRegexReplaceAll` return template
errors for invalid patterns. No-match replacement leaves its input unchanged:
keep explicit, anchored flow requirements rather than treating mapping as a
substitute for flow authorization.

## Boundaries

- `remote.user`, requesting-name requirements, audit/recording context and the
  transport name stored with a session retain `alice@host-a`.
- Credentials are checked for the resolved name. Simple lookup remains
  case-insensitive, htpasswd remains case-sensitive and native lookup follows
  its existing platform rules. Mapping does not trim or case-normalize output.
- With custom mapping, output must be nonempty, valid UTF-8, at most 1,024 bytes
  and contain no control characters. Missing context, invalid regexes or invalid
  output reject authorization; there is no retry with the original name.
- For `simple`/`local` user certificates, the resolved name is also the required
  certificate principal. A certificate for `alice` can therefore serve both
  example flows **only if their original-name/host/slug requirements and current
  credential/account policies allow it**. CA, validity, signature, critical
  option and capability restrictions remain unchanged.
- Sessions remain flow- and original-name-bound. A remembered key or browser
  possession proof cannot be used to switch to a newly mapped subject. Native
  resumption additionally retains current UID/SID and account-policy checks.
  A custom mapping that cannot be resolved from the current resume request or
  cannot be tied to the same native account rejects resumption; it does not
  replay a password or fall back to another flow. The default native nameless
  resume behavior is unchanged.
- `authorization.principal` is a separate, **post-authentication** display/target
  principal mapping. It does not select credentials and is not replaced by this
  property. Sharing an authorization definition is not cross-flow SSO or an
  automatic login/RememberMe opt-in.
