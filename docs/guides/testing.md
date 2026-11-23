---
description: Write your first configuration test, check an expected denial, and save results for CI.
---

# Test a configuration

Suppose your configuration should send requests for `ops` to an SSH target.
After authentication returns account `alice`, a rule should map her name to
`mapped-alice`. A request for `guest` should match no flow.

This guide turns those expectations into tests. You need a Bifröst binary and
a directory where you can create files. You do **not** need an SSH server, a
running Bifröst service or an actual Alice account.

## What you are testing

You provide the rules and an invented situation; Bifröst calculates the result:

| Part | In this example |
| --- | --- |
| Configuration | Only `ops` matches flow `primary`; prefix the authenticated name with `mapped-`. |
| Account facts | Account `alice` exists for the test. |
| Input | Request `ops`; assume flow `primary` authenticated Alice. |
| Calculated result | Select `primary` and target user `mapped-alice`. |
| Assertions | Check that the returned decision, flow and names match. |

Authentication is assumed, not performed. A `selected` result means the
supported selection rules succeeded, **not that a login or session succeeded**.
The [scope reference](../reference/testing/index.md#scope)
describes exactly which rules are evaluated.

## 1. Choose the configuration {: #configuration }

Test the same YAML file you intend to use when running Bifröst. You select it
when invoking `bifroest test`, rather than copying it into the tests directory
or fixing its path in a suite.

For this walkthrough, save the following example as `configuration.yaml` in
your project directory. When adapting the guide to an existing configuration,
use that file and adjust the test cases to its flows and rules instead.

```yaml title="configuration.yaml"
flows:
  - name: primary
    requirement:
      includedRequestingName: '^ops$'
    authorization:
      type: local
      principal: 'mapped-{{ .authentication.principal }}'
    environment:
      type: ssh
      address: work.example.org
      user: '{{ .authentication.principal }}'
      acceptAllHostKeys: true
      portForwardingAllowed: false
```

The `principal` template adds `mapped-` to the authenticated name. The `user`
template then uses that mapped principal as the SSH target user. These are
Bifröst's normal YAML templates, not Lua expressions.

!!! note "Offline example, not a deployment configuration"
    No connection to `work.example.org` is made. `acceptAllHostKeys` avoids
    requiring trust material in this fixture; do not copy that setting into
    a production gateway without proper [target trust](../reference/environment/ssh.md).

## 2. Describe the situation {: #write-a-suite }

Create a `tests` directory beside `configuration.yaml` and save
`tests/access_bftest.lua`. Bifröst recognizes the `_bftest.lua` suffix.
This file declares a suite called `access` with one test; it does not select a
configuration file.

A few Lua conventions explain the example:

- `suite { ... }` calls `suite` with a table. It is equivalent to `suite({ ... })`.
- `object { ... }` supplies named data; `list { ... }` supplies ordered items.
- `verify = function(t, actual) ... end` is called with the test context `t`
  and Bifröst's calculated result `actual`. `t:IsEqual` records a comparison.

The account below uses Linux/macOS facts. On Windows, apply the changes in
[Windows account facts](#windows) before running it.

```lua title="tests/access_bftest.lua"
suite {
  name = "access",
  platform = { os = { "unix" } },
  environment = object {
    accounts = list { object { name = "alice", uid = 1001 } },
  },
  tests = {
    {
      name = "ops-selects-target",
      input = object {
        request = object { requestingName = "ops" },
        authentication = object {
          primary = object { outcome = "allow", account = "alice" },
        },
      },
      verify = function(t, actual)
        t:IsEqual("selected", actual.decision)
        t:IsEqual("primary", actual.flow)
        t:IsEqual("mapped-alice", actual.identity.principal)
        t:IsEqual("mapped-alice", actual.environment.user)
      end,
    },
  },
}
```

Here, `authentication.primary` refers to **the YAML flow named `primary`**.
It does not refer to the suite name or the requested username. `allow` tells
the test to assume that flow authenticated `alice`; it does not supply the
expected final decision.

`suite.environment` describes the users available to the test.
`actual.environment` describes the resulting SSH target. Despite the shared
property name, those objects have different roles.

UID `1001` is invented test data, not an account to look up on your computer.

### Windows account facts {: #windows }

Change `platform` to `{ os = { "windows" } }` and replace the account object with:

```lua
object { name = "alice", sid = "S-1-5-21-1-2-3-1001" }
```

The SID is also invented. No account needs to be created on Windows. This
example selects an SSH target; the additional shell settings for a local
Windows target are explained in [Environment facts](../reference/testing/local.md#target-projection).

## 3. Run the test {: #run }

From the directory containing `configuration.yaml` and `tests`, run:

```shell
bifroest test tests --configuration configuration.yaml
```

`--configuration` selects the YAML file to test. Its path is relative to your
shell's working directory, **not the suite directory**. The suite contains only
the test situations and assertions, so it can test the same file you later use
for Bifröst without maintaining a separate configuration copy.

The command exits with status 0 and ends with:

```text
RESULT: 1 PASSED, 0 FAILED, 0 SKIPPED
```

Use `bifroest test tests --configuration configuration.yaml --verbose` to see
the suite and case name as well.
An assertion mismatch returns 1; invalid input, an empty selection or a test
execution/report error returns 2. See [the command reference](../reference/cli/test.md)
for flags and the full exit-code rules.

The CLI path is a fallback: an explicit `suite.configuration` takes precedence.
Leave that property out when testing the configuration selected by the command.
Dedicated, self-contained fixtures can still use it; see
[configuration selection](../reference/testing/suites.md#configuration).

## 4. Add an expected denial {: #denial }

Place this local variable **before `suite { ... }`** in the same file:

```lua title="Denied test"
local deniedRequest = {
  name = "guest-has-no-flow",
  input = object {
    request = object { requestingName = "guest" },
    authentication = object {},
  },
  verify = function(t, actual)
    t:IsEqual("deny", actual.decision)
  end,
}
```

Add `deniedRequest,` at the start of the suite's `tests` array, immediately
before the existing `{ name = "ops-selects-target", ... }` test table.

The `guest` request does not match `^ops$`, so no flow attempts authentication.
It needs no assumed authentication outcome. A denial is the expected result:
the **test passes because Bifröst denied the request**.

Run again; the summary now shows two passes. To select only the first scenario:

```shell
bifroest test tests --configuration configuration.yaml --includes '^access/ops-'
```

## 5. See a failure and save CI results {: #ci }

Change the expected principal in the first test from `mapped-alice` to
`wrong-user`. Its assertion now fails with a source line, expected/actual
values and exit status 1. Restore the correct expectation afterward.

Save both machine-readable reports with:

```shell
bifroest test tests --configuration configuration.yaml --json reports/testing.json --junit reports/testing.xml
```

Let the exit status fail your CI step. Upload reports even after a failed step
and use your CI's JUnit viewer for case names and failure details. Parent
directories are created and existing regular reports can be replaced; see
[report files](../reference/testing/reports.md#report-files) for protections and
write-failure behavior. Use synthetic values: assertion details may appear in reports.

## Run automatically in GitHub Actions {: #github-actions }

To check these tests on every push and pull request, use the
[GitHub Actions workflow](../setup/github-actions.md#configuration-tests).
It checks out your configuration and suites, installs Bifröst with
`engity-com/bifroest-action` and runs the tests. A failed test fails the job.

## Run in a container {: #container-execution }

The same command is available in the normal Bifröst image. See the
[restricted container example](../reference/testing/isolation.md#container-execution)
for read-only inputs, non-root execution and report mounts.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| No tests selected | Filename suffix, filters and the binary's [platform](../reference/testing/suites.md#platform). |
| A required account or field is unknown | Supply it in [the test facts](../reference/testing/local.md); omission does not mean absence. |
| The configuration cannot be loaded | Check `--configuration` relative to your invocation directory; see [configuration selection](../reference/testing/suites.md#configuration). |
| A template is unsupported | Check the [supported template subset](../reference/testing/isolation.md#templates). |
| Assertions pass, but exit status is 2 | Check report paths and the filesystem cause on stderr. |

## Next steps

- Look up [Lua functions](../reference/testing/lua.md), [Suites](../reference/testing/suites.md), [Tests](../reference/testing/tests.md) or [result fields](../reference/testing/result.md).
- Model [HTTP requests](../reference/testing/requests.md) or [OIDC data](../reference/testing/oidc.md).
- Browse the <<asset_link("pkg/test/README.md", "complete runnable examples")>>.
