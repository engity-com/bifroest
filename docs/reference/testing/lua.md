---
description: Look up the Lua functions and values provided when writing a Bifröst test suite.
---

# Functions and values

Bifröst supplies the functions on this page to every test file. You do not
import a module or install Lua separately. For a complete first suite, see
[the guide](../../guides/testing.md).

## Reading the syntax {: #syntax }

Lua uses `{ ... }` to write a table of named properties or numbered items:

```lua
local account = { name = "alice", uid = 1001 }
local names = { "alice", "bob" }
```

`local` declares a variable. `account.name` reads a named property;
`names[1]` reads the first item. Lua lists start at **1**, not 0.

`suite { ... }` is a function call, not a special declaration language. Lua lets
you omit parentheses when the only argument is a table: it means
`suite({ ... })`. The same applies to `object { ... }` and `list { ... }`.

`function(t, actual) ... end` defines the verification function. The runner
provides `t` and `actual` when it calls that function. The colon in
`t:IsEqual(...)` calls a method on `t`; keep it when writing assertions.

## `suite(definition)` {: #function-suite }

Register the tests in this file. Call it exactly once in every suite file.

### Arguments

<<property("definition", "Suite", "suites.md#suite", required=True, id_prefix="suite-", heading=4)>>
An ordinary Lua table describing the suite. Its `tests` property contains
ordinary [Test](tests.md) tables; their input data uses `object` and `list` as below.

### Return value and errors

No return value. Invalid declarations or a second registration in the same
file are errors, even if caught with `pcall`.

See the [Suite properties and example](suites.md#suite).

## `object(fields)` {: #function-object }

Create a read-only object with named fields. Use it for test input, environment
facts and object-valued expectations, including an empty object.

### Arguments

<<property("fields", "Lua table", required=True, id_prefix="object-", heading=4)>>
String-keyed fields whose values are supported [data values](data-types.md#data-value).
Use `list` for arrays. Cycles, metatables and unsupported values are errors.

### Return value

A read-only object containing a copy of the supplied values. Changing the
original table does not change the object. Writing to the returned object or
reading a missing named field is an error.

### Example

```lua
local account = object { name = "alice", uid = 1001 }
local emptyObject = object {}
```

## `list(items)` {: #function-list }

Create a read-only ordered list. Use it when the distinction between an empty
list and an empty object matters.

### Arguments

<<property("items", "Lua array", required=True, id_prefix="list-", heading=4)>>
A table with consecutive integer keys starting at 1 and no gaps. Items must be
supported [data values](data-types.md#data-value). Named keys, cycles and metatables are errors.

### Return value

A read-only copy of the list. `values[1]` reads its first item and `#values`
returns its length. An out-of-range integer index returns Lua `nil`. Generic
`pairs`/`ipairs` iteration over these read-only views is not supported; those
functions can still be used with ordinary Lua tables while generating tests.

### Example

```lua
local accounts = list { object { name = "alice", uid = 1001 } }
local emptyList = list {}
```

## `file_content(path)` {: #function-file-content }

Read a fixture file as text. Most suites use this to obtain their YAML
configuration; the function does not load or execute Lua code.

### Arguments

<<property("path", "string", required=True, id_prefix="file-content-", heading=4)>>
A relative path below the physical directory containing the suite file.
It is **not relative to your shell's working directory**.

### Return value and errors

The file's contents as a string. An unreadable or nonregular file, absolute
path, traversal, escaping symlink or exceeded file limit is an error. Relative
internal symlinks are supported; absolute symlinks are rejected even if they
point inside the directory. Caught read errors still fail the suite/test.

The first successful read of each path is reused for that suite's tests,
including reads first made inside a verification function. A discovery symlink
does not change the allowed physical directory. The in-memory Go runner has
no suite directory and cannot use this function. See [file limits](isolation.md#limits).

### Example

```lua
local configuration = file_content("configuration.yaml")
```

## `null` {: #null }

A value for **known absence**, where a field accepts it. It is not a function.
Lua `nil` removes a table field; `null` keeps an explicit value in the data.

```lua
local knownAbsent = object { token = null }
local unknown = object {}
```

For OIDC, the first object says the OAuth token is absent; the second supplies
no information about it. A missing observation can fail a test when the rule
needs it. Not every field accepts null: follow its property documentation.

## Data values {: #data-values }

The [Data value](data-types.md#data-value) type defines the supported strings,
numbers, booleans, objects, lists and null/omission rules. Shared types such as
[Name](data-types.md#name) describe more specific values used by properties;
they do not require you to instantiate a class.

Other functions, supported syntax and runtime bounds are documented under
[isolation and limits](isolation.md#lua).
