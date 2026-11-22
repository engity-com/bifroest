---
description: Test how your Bifröst configuration selects flows and maps users without logging in or starting a session.
---

# Testing

A configuration test answers questions such as: **“When Alice requests `ops`,
does this configuration choose the expected flow and SSH target user?”**

You supply a configuration and describe a situation. Bifröst evaluates its rules
for that situation. Your test then compares the result with your expectations.
For a step-by-step introduction, see [Test a configuration](../../guides/testing.md).

## How a test works

| Part | What you provide or receive |
| --- | --- |
| [Configuration](suites.md#configuration) | The YAML rules you want to test. |
| [Environment facts](local.md#environment) | Users and groups that should exist, or be known not to exist, for this test. These are not read from your computer. |
| [Input](input.md#input) | A request and the authentication results the test should assume. |
| [Result](result.md#result) | The flow, identity and target settings calculated by Bifröst. |
| [Assertions](assertions.md) | Comparisons between that result and what you expected. |

For example, the test can assume that authentication returned local account
`alice`. It can then check that the configuration maps Alice's name to
`mapped-alice` and chooses that user on an SSH target. It does not check Alice's
password or connect to the target.

A **suite** groups tests that share configuration and environment facts. Save
each suite in a file named `*_bftest.lua`, then run it with
[`bifroest test`](../cli/test.md).

## Example

Save the configuration you want to test as `configuration.yaml`:

```yaml title="configuration.yaml"
flows:
  - name: primary
    requirement: { includedRequestingName: '^ops$' }
    authorization: { type: local }
    environment:
      type: ssh
      address: work.example.org
      user: alice
      acceptAllHostKeys: true
```

In the same directory, save the test suite as `access_bftest.lua`:

```lua title="access_bftest.lua"
suite {
  name = "access",
  environment = object {},
  tests = {
    {
      name = "guest-has-no-flow",
      input = object { request = object { requestingName = "guest" } },
      verify = function(t, actual)
        t:IsEqual("deny", actual.decision)
      end,
    },
  },
}
```

The configured flow matches only `ops`, so the `guest` request matches no flow.
No account facts or authentication outcomes are needed. The test passes because
the calculated denial matches the assertion. No connection to the SSH target is
made; the SSH settings, including `acceptAllHostKeys`, are only fixture data.

From that directory, run:

```shell
bifroest test -c configuration.yaml .
```

`-c` selects the configuration file. `.` finds all `*_bftest.lua` files in the
current directory and its subdirectories.

The result is `1 PASSED, 0 FAILED, 0 SKIPPED` and exit status 0. For a positive
selection example, continue with [the guide](../../guides/testing.md).

## Lua reference

Use these pages to look up a function or data type while writing a test:

| Reference | Contains |
| --- | --- |
| [Functions and values](lua.md) | `suite`, `object`, `list`, `file_content`, `null` and the small amount of Lua syntax you need. |
| [Suites](suites.md) | Shared configuration, environment facts, the test list and platform selectors. |
| [Tests](tests.md) | Individual test properties: name, input and verification function. |
| [Input](input.md) | Request and Authentication assumption properties. |
| [Requests](requests.md) | SSH/HTTP request properties and method selection. |
| [Environment facts](local.md) | Account, group and explicit-absence properties. |
| [OIDC data](oidc.md) | OIDC identity, OAuth token, ID token and UserInfo properties. |
| [Test context](context.md) | The `t` argument passed to your verification function. |
| [Results](result.md) | The `actual` argument: decision, identity and target settings. |
| [Assertions](assertions.md) | `t:IsEqual(expected, actual, reason?)`. |
| [Data types](data-types.md) | Shared value types such as Name, authentication modes, selectors and identifiers. |

For command arguments and filters, use the [CLI reference](../cli/test.md).
For output formats, use [Reports](reports.md).

## Scope and limitations {: #scope }

The testing scope is
`post-authentication/session-target`: configuration validation, SSH/HTTP flow
selection, identity mapping, and SSH/local target settings. The local
environment's `loginAllowed` rule is also evaluated. These use the same rules as
the running service, within the [supported template subset](isolation.md#templates).

!!! warning "A selected target is not a successful login"
    `actual.decision = "selected"` means these selection steps succeeded.
    Authentication is assumed. Credentials, native account eligibility, target
    connections, sessions and effective runtime permissions have not been tested.

No service, HTTP listener, browser, IdP exchange, host-account lookup,
provisioning or target process is started. HTTP endpoint checks such as TLS,
domain allowlists and browser Origin/CSRF are outside this test. Token
signatures and lifetimes are not verified. Authentication types and targets
outside the supported local/OIDC and SSH/local combinations return errors when
needed; they are not silently treated as denials.

An expected `deny` can be a **passing test**. Invalid configuration, missing
required facts or unsupported behavior are **errors**, not a successful denial.
See [isolation and limits](isolation.md) for available Lua features, resource
bounds and the distinction from an OS sandbox.
