---
description: How to access context information about a user that wants to authorize with Bifröst.
---

# Context Authorization Request

Represents a request for authorization of a remote user/connection.

There are more specialized variants of the authorization request available, based on their actual usage:

* [Public Key](#public-key)
* [Password](#password)
* [Interactive](#interactive)

## Properties

<<property("remote", "Remote", "remote.md")>>

Identifies the user with its host and username.

## Public Key

Is used at the attempt to use the authentication method `publickey` where the user's client presents one of the user's [SSH Public Keys](../data-type.md#ssh-public-key).

### Properties

All inherited of [Context Authorization Request](#properties) plus:

<<property("publicKey", "SSH Public Key", "../data-type.md#ssh-public-key", id_prefix="publicKey-", heading=4)>>

The provided [SSH Public Key](../data-type.md#ssh-public-key) of the requesting remote user.

## Password

Is used at the attempt to use the authentication method `password` where the user's client presents the password the user either handed over directly to the SSH client software via command line, stdin or when the client asks for it.

### Properties

All inherited of [Context Authorization Request](#properties) plus:

<<property("password", "string", id_prefix="password-", heading=4)>>

The provided password.

## Interactive

Is used at the attempt to use the authentication method `keyboard-interactive` where the user's client give the control to the server to interactively request more information from the user. Usually, this is another way to request either the password or multi-factor-information.

### Properties

All inherited of [Context Authorization Request](#properties), but no other.
