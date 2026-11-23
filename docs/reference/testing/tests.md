---
description: Properties of one test in a suite, including its input and verification function.
---

# Tests {: #test }

A test is one entry in a [suite's `tests` array](suites.md#property-tests).
It describes one situation through `input` and checks Bifröst's calculated
result through `verify`. The suite supplies the shared configuration and
environment facts.

## Properties

<<property("name", "Name", "data-types.md#name", required=True, heading=3)>>
The case's name, unique within its suite. Reports and CLI filters use
`suite.name/test.name`.

<<property("input", "Input", "input.md#input", required=True, heading=3)>>
An object describing the request and assumed authentication outcomes for this
case. It does not contain the expected result; assertions supply that.

<<property("verify", "function(t, actual)", required=True, heading=3)>>
A Lua function receiving [Test context](context.md#context) as `t` and
[Result](result.md#result) as `actual`. Run at least one
[`t:IsEqual`](assertions.md#method-is-equal) assertion. Its return value is ignored.

## Example

This test uses the configuration and account facts from
[the first-test guide](../../guides/testing.md). Define it before `suite { ... }`:

```lua title="Test definition"
local selectedUser = {
  name = "selected-user",
  input = object {
    request = object { requestingName = "ops" },
    authentication = object {
      primary = object { outcome = "allow", account = "alice" },
    },
  },
  verify = function(t, actual)
    t:IsEqual("selected", actual.decision)
    t:IsEqual("mapped-alice", actual.environment.user)
  end,
}
```

Use `tests = { selectedUser }` in the suite, or add `selectedUser,` to its
existing `tests` array.

## Execution

Each selected test starts with a fresh Lua VM and replays the suite declaration.
Globals and captured local variables therefore do not carry state from a
previous test. Write declarations that produce the same inputs on each replay.
