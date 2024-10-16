---
description: In many places Bifröst can be customized using templating. How does they work?
---

# Templating

In many places of the [configuration](../configuration.md) Bifröst can not only be customized by using static strings or numbers, but by using templates as well.

Bifröst uses the [template engine of Go](https://pkg.go.dev/text/template). A collection of rather good resources to learn can be found at [HashiCrop's Nomand Developer documentation](https://developer.hashicorp.com/nomad/tutorials/templates/go-template-syntax).

In the documentation of each Bifröst's component you can find the type (like [String Template](#string) or [Bool Template](#bool)) and the corresponding [context object](../context/index.md) (like [Connection](../context/connection.md) or [Authorization](../context/authorization.md)). The result will be like:

* [String Template](#string)&lt;[Authorization](../context/authorization.md)&gt;
* [Bool Template](#bool)&lt;[Connection](../context/connection.md)&gt;

## Variants

### String {: #string}

A template of type String is always rendered to a corresponding string - as it is.

Examples:

* `Foo{{ "Xyz" }}Bar` or will result in `FooXyzBar`.
* `Foo{{ 123 }}Bar` or will result in `Foo123Bar`.

### Strings {: #strings}

This is simply an array of [String](#string) = **Array<[String](#string)>** and will result in Array<string>.

Examples:

```yaml title="Input"
foos:
  - Foo{{ "Xyz" }}Bar
  - Foo{{ 123 }}Bar
```

```yaml title="Result"
foos:
  - FooXyzBar
  - Foo123Bar
```

### URL {: #url}

This is similar to [String](#string) and will result in the data type [URL](../data-type.md#url).


### Bool {: #bool}

A template of type Bool is always rendered into a boolean value (`true` or `false`). The following rules are evaluated to decide for either `true` or `false`:

* `false`: If the value trimmed and converted to lower-cases is one of: `false`, `disabled`, `0`, `no`, `off`, &lt;empty&gt;, `nil` or `null`
* `true`: Everything else

### Uint32 {: #uint32}

A template of type Uint32 is always rendered into an unsigned integer with 32 bits value (`0` or more). An empty value is always assumed as `0`.
