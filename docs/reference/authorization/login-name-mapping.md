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

## SSH suffix and HTTP slug

The SSH login name `foo@bar` can select a flow while checking account `foo`.
For HTTP, leave the login name unchanged and choose the same flow with `/docker`:

```yaml
environments:
  default: {type: dummy}
authorizations:
  shared:
    type: simple
    remoteName: '{{if eq .connection.transport "ssh"}}{{regexReplaceAll "@[^@]+$" .remote.user ""}}{{else}}{{.remote.user}}{{end}}'
    entries:
      - name: foo
        passwordFile: /etc/engity/bifroest/passwords/foo
flows:
  - name: docker
    discoverAsSlug: docker
    requirement:
      ssh:
        includedRequestingName: '@bar$'
      http:
        includedSlug: '^docker$'
    authorization: shared
```

This example demonstrates credential selection only; replace the dummy
environment with reviewed target environments. To avoid ambiguity in an SSH
client's destination parser, use `ssh -l 'foo@bar' bifroest.example.org`. In the
browser, open `/docker` and sign in as `foo`. The HTTP name `foo@bar` is **not**
silently shortened by this conditional template.

The general `requirement.includedRequestingName: '^docker$'` would match the
literal original username `docker` for both transports, not the suffix `@bar`,
the flow name, the mapped account `foo`, or the HTTP slug. Keep SSH name and HTTP
slug restrictions in their respective transport sections when combining them.
See [flow requirements](../flow.md#requirement) and the current incoming
[connection metadata](../context/connection.md).

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
  transport name stored with a session retain the original name (`foo@bar` for
  SSH in the combined example).
- Credentials are checked for the resolved name. Simple lookup remains
  case-insensitive, htpasswd remains case-sensitive and native lookup follows
  its existing platform rules. Mapping does not trim or case-normalize output.
- With custom mapping, output must be nonempty, valid UTF-8, at most 1,024 bytes
  and contain no control characters. Missing context, invalid regexes or invalid
  output reject authorization; there is no retry with the original name.
- For `simple`/`local` user certificates, the resolved name is also the required
  certificate principal. A certificate for `foo` can therefore serve configured
  suffix-selected flows **only if their original-name/host/slug requirements and current
  credential/account policies allow it**. CA, validity, signature, critical
  option and capability restrictions remain unchanged.
- Sessions remain flow- and original-name-bound. A remembered key or browser
  possession proof cannot be used to switch to a newly mapped subject. Native
  resumption additionally retains current UID/SID and account-policy checks.
  A custom mapping that cannot be resolved from the current resume request or
  cannot be tied to the same native account rejects resumption; it does not
  replay a password or fall back to another flow. The default native nameless
  resume behavior is unchanged.
  In particular, SSH `foo@bar` and HTTP `foo` can use the same credentials without
  automatically merging their sessions or changing their stored original names.
- `authorization.principal` is a separate, **post-authentication** display/target
  principal mapping. It does not select credentials and is not replaced by this
  property. Sharing an authorization definition is not cross-flow SSO or an
  automatic login/RememberMe opt-in.
