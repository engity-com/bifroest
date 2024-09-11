---
description: A collection of simple data-types used within Bifröst.
toc_depth: 2
---

# Data types

A collection of simple data-types used within Bifröst. More complex ones are defined on their dedicated pages.

## Authorized Keys

These are usually files in the home directory of each user, located at `~/.ssh/authorized_keys`. These files are in the format:
```text
<key-type> <encoded-public-key>[ <comment>]
...
```

They contain [SSH Public Keys](#ssh-public-key).

### Examples
```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC80lm5FQbbyRUut6RwZJRbxTLO3W4f08ITDi9fA3+jx me@foo.tld
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDIGYzqJpPf3shQVGo98xMdl5S4LJmWme3i+sPcYseRrKziAWWGc8xzLUGnRwVe5X5v7J+IaHZ0dpnelylbnDwEvQTX+8gZybcL8RpS6u5dKqmKTv12SqcucpGStQ3O0Ec3MnRKEeMoJXIdqIVxuXxC8863H42KzkBvDjZn4qasF8IOVpGSC4+i93bNKScN6epQYzKcPCmZSSAnZJPgih0y1Z6+yNOJd+6PAFXmhBOh7yU0Ypne9szj/6o3YrPuNUj762CZyjg7ivQI/DvxwnUA2X8dnb2pyD4CGrr6YduWMl2xqUEDerNVaPc+I63QR8gIUYYmAs5uQwrDI4U0aWpC7erLMsNRa8C+YUdX+rV2+lJWSH8/k2NGrT1FoG5PWHmZTIe4juKIlAArzDAE6shauM3j4b4YLhly6mySXxT9m+EPtcrZjdEg76/0FylFUH70dx0Wf7lt50cLQIoXCJVovp/w95J6FVMYACl1y/sbDzmirg2PQkqkrr3MZnNY88jI/OuyZYAHNIjMkbriaFIkFBK4epGhsIIpsArPS8ZGZTQNBrrYWF+pf8JvJ1NaoLP+JKUP/A7l1KsqCKK3sWIRY7u8n8McK0VQMig4duHHtZ+aUGhZd/+m19UG1gg7QPUffZQM0RIPWWcsklrmlvzBqVcxgHXkZOoFqzc9WyewWQ== me-legacy@foo.tld
```

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

## File Mode
The permissions to access a file in octal notation. See [Oracles documentation](https://docs.oracle.com/cd/E19504-01/802-5750/6i9g464pv/index.html) for more details.

## File Path
A location of a file on the local file system. Like `/foo/bar`

## Host
Represents a host(-name), which can be either an [IPv4](https://en.wikipedia.org/wiki/IPv4), [IPv6](https://en.wikipedia.org/wiki/IPv6) or [DNS name](https://en.wikipedia.org/wiki/Domain_Name_System).

## Log Color Mode
Can be one of:

* `auto`
* `always`
* `never`

## Log Format
Can be one of:

* `text`
* `json`

## Log Level
Can be one of:

* `TRACE`
* `DEBUG`
* `INFO`
* `WARN`
* `ERROR`
* `FATAL`

## Net Address
Socket address in format <code>\[&lt;[Host](#host)&gt;]:&lt;port&gt;</code>.

## Password
Represents an encoded or plain password that can be evaluated if it does match a requested one.

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

## SSH Public Key
The public variant of an [SSH keypair](https://wiki.archlinux.org/title/SSH_keys) of a user.

Please refer to the [good documentation at GitHub how to create SSH (public) keys](https://docs.github.com/de/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).
