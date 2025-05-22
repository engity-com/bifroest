---
description: A collection of simple data-types used within Bifröst.
toc_depth: 2
---

## Arch (Architecture) {: #arch }
Represents an architecture. Here are all values supported where also a distribution of Bifröst is available for. See [distributions](../setup/distribution.md#compatibility) for available values.

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

## Docker Pull Credentials
To pull from an OCI/Docker image registry there can be credentials required. In these cases usually they have to be provided in this format.

Bifröst accept them in the following formats:

1. Base64 URL encoded JSON of format `{"username":"<username>","password":"<password>"}` or `{"auth":"<base64 encoded auth token>"}`
2. JSON of format `{"username":"<username>","password":"<password>"}` or `{"auth":"<base64 encoded auth token>"}` ... which will be:
    1. base64 URL encoded by Bifröst. -> result will be as 1.
3. A bare auth token ... which will be:
    1. base64 URL encoded,
    2. put into `{"auth":"<encoded bare auth token>"}` JSON and
    3. finally base64 URL encoded by Bifröst. -> result will be as 1.

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

## Kubeconfig
Configuration file in YAML format that defines how to access a Kubernetes cluster. See [official Kubernetes documentation](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) for more details.

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

## Os (Operating System) {: #os }
Represents an operating system. Here are all values supported where also a distribution of Bifröst is available for. See [distributions](../setup/distribution.md#compatibility) for available values.

## Password
Represents an encoded or plain password that can be evaluated if it does match a requested one.

## Password Type
Can be one of:

* `plain`
* `bcrypt`

## Pull Policy
Can be one of:

* `ifAbsend`: The resource (e.g. an image) is pulled only if it is not already present locally.
* `always`: Everytime a context is crated (for example a new environment) the latest version of the resource will be pulled from the remote registry (for example an image). It does not matter if the resource does already exist or not. No matter if the resource (like images) is based on digest or of the digest is the same, the digest is the same, the corresponding sub-resources will not be pulled.
* `never`: The resource (like an image) has to be present. Otherwise, the process will fail.

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

## SSH Ciphers
Can be one of:

* `aes128-cbc`
* `3des-cbc`
* `arcfour`
* `arcfour128`
* `arcfour256`
* `chacha20-poly1305@openssh.com`
* `aes128-ctr`
* `aes192-ctr`
* `aes256-ctr`
* `aes128-gcm@openssh.com`
* `aes256-gcm@openssh.com`

## SSH Key Exchange
Can be one of:

* `diffie-hellman-group1-sha1`
* `diffie-hellman-group14-sha1`
* `diffie-hellman-group14-sha256`
* `diffie-hellman-group16-sha512`
* `ecdh-sha2-nistp256`
* `ecdh-sha2-nistp384`
* `ecdh-sha2-nistp521`
* `curve25519-sha256@libssh.org`
* `curve25519-sha256`
* `diffie-hellman-group-exchange-sha1`
* `diffie-hellman-group-exchange-sha256`
* `mlkem768x25519-sha256`

## SSH Message Authentication
Can be one of:

* `hmac-sha1`
* `hmac-sha1-96`
* `hmac-sha2-256`
* `hmac-sha2-512`
* `hmac-sha2-256-etm@openssh.com`
* `hmac-sha2-512-etm@openssh.com`

## SSH Public Key
The public variant of an [SSH keypair](https://wiki.archlinux.org/title/SSH_keys) of a user.

Please refer to the [good documentation at GitHub how to create SSH (public) keys](https://docs.github.com/de/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).

## URL
Represents a classical [URL](https://en.wikipedia.org/wiki/URL) to reference resources (for example) in the internet, like [https://bifroest.engity.org](https://bifroest.engity.org).
