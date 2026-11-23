---
description: Look up the read-only Test context passed as t to a Lua verification function.
---

# Test context {: #context }

The runner calls your verification function with two arguments, `t` and `actual`.
`t` gives access to the test's original data and assertion methods.
`actual` is the separately calculated [Result](result.md). You may use different
argument names, but their positions have these meanings.

All data properties are read-only. Write expectations with the
[`IsEqual` method](assertions.md#method-is-equal).

## Properties

<<property("input", "Input", "input.md#input", heading=3)>>
The original input supplied by this Test. For example,
`t.input.request.host` keeps the spelling you wrote, whereas
`actual.request.host` contains the canonical host used for matching.

<<property("environment", "Environment facts", "local.md#environment", heading=3)>>
The supplied suite facts: known users, groups and absences. This is **not**
`actual.environment`, which describes the selected target settings.

<<property("configuration", "Test configuration", "#configuration", heading=3)>>
A small view of the loaded configuration, described below. It is not the whole
YAML configuration and exposes no configuration secrets.

## Test configuration {: #configuration }

This is the value of `t.configuration`.

<<property("flows", array_ref("Test flow", "#flow"), heading=3)>>
The configured flows in configuration order. No authorizer or environment
configuration objects are exposed through this view.

## Test flow {: #flow }

Each entry in `t.configuration.flows` has one property:

<<property("name", "Flow Name", "../data-type.md#flow-name", id_prefix="flow-", heading=3)>>
The configured flow name. For example, `t.configuration.flows[1].name`.

## Methods

[`t:IsEqual(expected, actual, reason?)`](assertions.md#method-is-equal) compares
values and records the result as an assertion.

## Examples

The callback's basic shape is:

```lua
local function verify(t, actual)
  t:IsEqual("selected", actual.decision)
end
```

Inside a verification function for the first-test guide:

```lua
local function verify(t, actual)
  t:IsEqual("ops", t.input.request.requestingName)
  t:IsEqual("alice", t.environment.accounts[1].name)
  t:IsEqual("mapped-alice", actual.environment.user)
end
```

The three names are deliberately different: requested name, assumed account,
and selected SSH target user.

## Reading values

Use field access for objects and 1-based indexing or `#` for lists. Reading a
missing named field is an error; it does not turn into a guessed value. There
is no generic iteration over these read-only views. See
[Data value](data-types.md#data-value) for data types and null/omission rules.
