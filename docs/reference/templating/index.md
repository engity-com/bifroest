---
description: In many places Bifröst can be customized using templating. How does they work?
---

# Templating

In many places of the [configuration](../configuration.md) Bifröst can not only be customized by using static strings or numbers, but by using templates as well.

Bifröst uses the [template engine of Go](https://pkg.go.dev/text/template). A collection of rather good resources to learn can be found at [HashiCrop's Nomand Developer documentation](https://developer.hashicorp.com/nomad/tutorials/templates/go-template-syntax).

In the documentation of each Bifröst's component you may find the type the icon [:material-file-replace-outline:{ title="Templated with Foobar" }](index.md), followed by the corresponding [context object](../context/index.md) (like [Connection](../context/connection.md) or [Authorization](../context/authorization.md)). The result will be like:

* [:material-file-replace-outline:{ title="Templated with Authorization" data-hint-type="templated" }](index.md) [Authorization](../context/authorization.md)
* [:material-file-replace-outline:{ title="Templated with Authorization" data-hint-type="templated" }](index.md) [Connection](../context/connection.md)

## Base types

Each base type ([string](#string), [bool](#bool), [uint32](#uint32), ...) has a different handling in edge cases.

### string {: #string}

A template of type String is always rendered to a corresponding string - as it is.

Examples:

* `Foo{{ "Xyz" }}Bar` or will result in `FooXyzBar`.
* `Foo{{ 123 }}Bar` or will result in `Foo123Bar`.

### bool {: #bool}

A template of type Bool is always rendered into a boolean value (`true` or `false`). The following rules are evaluated to decide for either `true` or `false`:

* `false`: If the value trimmed and converted to lower-cases is one of: `false`, `disabled`, `0`, `no`, `off`, &lt;empty&gt;, `nil` or `null`
* `true`: Everything else

### uint32 {: #uint32}

A template of type uint32 is always rendered into an unsigned integer with 32 bits value (`0` or more). An empty value is always assumed as `0`.

### float32 {: #float32}

A template of type float32 is always rendered into a floating point number with 32 bits value (`0.0` or more). An empty value is always assumed as `0`.
