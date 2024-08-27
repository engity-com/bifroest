---
description: A collection of simple data-types used within Bifröst.
---

# Data types

A collection of simple data-types used within Bifröst. More complex ones are defined on their dedicated pages.

## DSA Restriction
Can be one of:

* `none`
* `all`
* `at-least-1024-bits`
* `at-least-2048-bits`
* `at-least-3072-bits`

## Duration
A duration of time of [Go flavor](https://pkg.go.dev/time#ParseDuration). Examples: `300ms`, `6s`, `5m`, `12h` or combined `12h5m6s300ms`.

## ED25519 Restriction
Can be one of:

* `none`
* `all`
* `at-least-256-bits`

## ECDSA Restriction
Can be one of:

* `none`
* `all`
* `at-least-256-bits`
* `at-least-384-bits`
* `at-least-521-bits`

## Flow Name
Identifies flows. It has to fulfill the regular expression `[a-z][a-z0-9]+`.

## File Path
A location of a file on the local file system. Like `/foo/bar`

## Net Address
Socket address in format `[<host>]:<port>`.

## Regex
Regular expression of [Go flavor](https://pkg.go.dev/regexp). You can play around with it at [regex.com](https://regex101.com/r/fRdVOl/1).

## RSA Restriction
Can be one of:

* `none`
* `all`
* `at-least-1024-bits`
* `at-least-2048-bits`
* `at-least-3072-bits`
* `at-least-4096-bits`
