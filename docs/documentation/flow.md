---
toc_depth: 6
description: A flow represents a flow of a user's session from the authorization to the active environment. Bifröst can have one ore more.
---
# Flows

A flow represents a flow of a user's session from the [authorization](authorization/index.md) to the active [environment](environment/index.md). Bifröst cannot just interpret one flow, like the majority of the SSH server, it can interpret *one or more*. With this approach Bifröst can do something similar like HTTP servers implementing [Virtual hosting](https://en.wikipedia.org/wiki/Virtual_hosting) - but in this case it is based on the combination of the requesting usernames (see [requirement](#requirement)) and which [authorization](authorization/index.md) the user can fulfill.

For each configured flow, Bifröst will evaluate the following checks. If one of them does not succeed, Bifröst will end the evaluating of the current flow and will try the next one as long more candidates are available:

1. Is there already a matching [session](session/index.md) existing; if yes: Execute immediately into the environment of this [session](session/index.md) and skip the following evaluations.
2. Is the [requirement](#requirement) fulfilled?
3. Is the user successfully [authorized](authorization/index.md)?
4. Is the configured [environment](environment/index.md) able to handle the current [connection](connection/index.md) and [authorization](authorization/index.md)?
5. Is it possible to create a [session](session/index.md) for the combination of [connection](connection/index.md), [authorization](authorization/index.md) and [environment](environment/index.md)?

## Configuration

<<property("name", "Flow Name", "data-type.md#flow-name", None, True)>>
:   Defines the unique name of the flow. It will be used inside logs, as references for the stored [sessions](session/index.md), ...

    !!! warning
        Changing this value afterward means to break all existing sessions.

<<property("requirement", "Requirement", "#requirement")>>
:   See [Requirement](#requirement), below.

<<property("authorization", "Authorization", "authorization/index.md", True)>>
:   Will be evaluated to ensure the requesting user is allowed to access [the environment of this flow](#property-environment).

<<property("environment", "Environment", "environment/index.md", True)>>
:   Once all requirements are fulfilled and the user is authorized successfully, he will execute into this [environment](environment/index.md).

## Example

```yaml
flows:
  - name: sso
    requirement:
      includedRequestingName: ^sso$
    authorization:
      type: oidc
      # ...
    environment:
      type: local
      # ...

  - name: local
    authorization:
      type: local
      # ...
    environment:
      type: local
      # ...
```

## Requirement

The requirement has to be fulfilled, before even the [authorization](#property-authorization) is evaluated.

### Configuration {: id=requirement-configuration }

<<property("includedRequestingName", "Regex", "data-type.md#regex", "\"\"", False, "requirement-", 4)>>
If this property is set, the requesting name (`ssh <requesting name>@my-host.tld`) has to fulfill this regular expression. If empty everything will be included.

!!! warning
    Keep `^` and `$` to ensure a full match, otherwise it matches only a part of it.

<<property("excludedRequestingName", "Regex", "data-type.md#regex", "\"\"", False, "requirement-", 4)>>
If this property is set, the requesting name (`ssh <requesting name>@my-host.tld`) has to **NOT** fulfill this regular expression. If empty everything will be included.

!!! warning
    Keep `^` and `$` to ensure a full match, otherwise it matches only a part of it.

### Example {: id=requirement-example }

```yaml
requirement:
  includedRequestingName: ^foo$
  excludedRequestingName: ^bar$
```

## Next topics
* [Configuration](configuration.md)
* [Environments](environment/index.md)
* [Authorizations](authorization/index.md)
