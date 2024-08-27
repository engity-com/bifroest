---
description: Documentation is Bifröst, how it can be configured and operated.
---
# Introduction

## Concept

Bifröst does have the following important entities:

1. [**Connection**](connection/index.md) which is established by the user's SSH client to Bifröst.

2. [**Authorization**](authorization/index.md) are used to authorize the user and acquire more relevant information, needed for successful execution.

3. [**Environment**](environment/index.md) is the place where the user is executed into; the target shell where to user executes its tasks.

4. The [**Session**](session/index.md) will be created for the user when the [authorization](authorization/index.md) was successful and an [environment](environment/index.md) **can** be created. It is used to identify the current [connection](connection/index.md) and any subsequent session.

5. Bifröst can have one or more [**Flows**](flow.md). This can define different combinations of [authorizations](authorization/index.md) and [environments](environment/index.md) based on different rules. This is comparable with [Virtual hosting](https://en.wikipedia.org/wiki/Virtual_hosting) like HTTP server are already providing it since years.

## Next topics

1. [Installation](../getting-started.md)
2. [Configuration](configuration.md)
3. [Command line interface (CLI)](cli.md)
