---
description: Compare expected and actual values with the Lua Test context's IsEqual method.
---

# Assertions

An assertion states what should be true about a test's result. Bifröst records
each comparison and reports any mismatch with its source line and values.
Call assertions inside the test's [`verify`](tests.md#property-verify)
function, using the [Test context](context.md) supplied as `t`.

## `t:IsEqual(expected, actual, reason?)` {: #method-is-equal }
<span id="equality"></span>

Compare two values. Use the colon (`:`) to call this method on `t`.

### Arguments

<<property("expected", "Data value or nil", "data-types.md#data-value", required=True, id_prefix="is-equal-", heading=4)>>
The value your test expects. Put it first so the failure report reads in the
right direction.

<<property("actual", "Data value or nil", "data-types.md#data-value", required=True, id_prefix="is-equal-", heading=4)>>
The value to compare, usually a field of the Result passed to `verify`.

<<property("reason", "string", optional=True, id_prefix="is-equal-", heading=4)>>
An explanation included in a failure report, at most 256 bytes. Use it to say
why the expectation matters. Do not put secrets in assertion values or reasons.

### Return value

`true` when the values match, otherwise `false`. A mismatch records a failure
but does not stop the function, so subsequent assertions can also run. Ignoring
the return value does **not** ignore the failure.

### Comparison rules

- Values must have the same type: integer `1` differs from float `1.0`.
- Strings and booleans compare exactly; strings are not normalized.
- Objects compare their fields recursively; lists compare length, item types,
  values and order. Use `object`/`list` for composite expectations.
- Explicit `null` differs from an omitted Lua `nil` value.

### Errors

An invalid call, unsupported value, overlong/non-string reason or exceeded
assertion limit is an execution error. Catching it with `pcall` does not turn
the test into a pass. A valid mismatch inside `pcall` also remains recorded.

Every selected test must execute at least one `t:IsEqual` assertion. Lua's
ordinary `assert(...)` is not a recorded testing assertion and does not satisfy
that requirement.

### Example

Use this function as a Test's `verify` property:

```lua
local function verify(t, actual)
  t:IsEqual("selected", actual.decision)
  t:IsEqual("mapped-alice", actual.environment.user, "Use the mapped SSH account")
end
```

When expecting a denial, check its decision without reading fields that only
exist on selection:

```lua
local function verifyDenial(t, actual)
  t:IsEqual("deny", actual.decision)
end
```

See [Results](result.md) for field availability and [Reports](reports.md) for
the distinction between assertion failures, execution errors and platform skips.
