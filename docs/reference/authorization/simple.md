---
toc_depth: 4
description: How to authorize a requesting user the simplest way with Bifröst.
---

# Simple authorization

Authorizes a requesting user via stored credentials.

## Properties

<<property("type", "Authorization Type", default="simple", required=True)>>
Has to be set to `simple` to enable simple authorization.

<<property_with_holder("entries", "Array", None, "Entry", "#entry")>>
Each entry will be inspected to try to authorize a remote user.

## Entry

Always one property of the following properties has to match in combination with [`name`](#entry-property-name):

* [`authorizedKeys`](#entry-property-authorizedKeys)
* [`authorizedKeysFile`](#entry-property-authorizedKeysFile)
* [`password`](#entry-property-password)

### Properties {: #entry-properties }

<<property("name", "string", id_prefix="entry-", heading=4, required=True)>>
Name the remote user has to have.

Like: `ssh <name>@my-great-domain.tld` to match this entry.

<<property("authorizedKeys", "Authorized Keys", "../data-type.md#authorized-keys", id_prefix="entry-", heading=4)>>
Contains [SSH Public Keys](../data-type.md#ssh-public-key) in the format of classic [authorized keys](../data-type.md#authorized-keys).

<<property_with_holder("authorizedKeysFile", "File Path", "../data-type.md#file-path", "Authorized Keys", "../data-type.md#authorized-keys", id_prefix="entry-", heading=4)>>
Similar to [`authorizedKeys`](#entry-property-authorizedKeys), but in a dedicated file.

<<property("password", "Password", "../data-type.md#password", id_prefix="entry-", heading=4)>>
Password (if user uses interactive or password authentication methods) to be evaluated against.

## Context

This authorization will produce a context of type [Authorization Simple](../context/authorization.md#simple).

## Examples

1. Using [plain password](#entry-property-password):
   ```yaml
   type: simple
   entries:
     - name: foo
       password: plain:bar
   ```
2. Using [authorized keys](#entry-property-authorizedKeys):
   ```yaml
   type: simple
   entries:
     - name: foo
       authorizedKeys: |
         ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC80lm5FQbbyRUut6RwZJRbxTLO3W4f08ITDi9fA3+jx foo@foo.tld
   ```

## Compatibility

| [`linux`/`generic`](../../setup/distribution.md#linux-generic) | [`linux`/`extended`](../../setup/distribution.md#linux-extended) | [`windows`/`generic`](../../setup/distribution.md#windows-generic) |
| - | - | - |
| <<compatibility(True)>> | <<compatibility(True)>> | <<compatibility(True)>> |
