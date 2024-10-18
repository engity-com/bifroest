---
description: An environment created for demonstration purposes, it simply prints a message and exists immediately.
toc_depth: 5
---

# Dummy environment

An environment created for demonstration purposes, it simply prints a message and exists immediately.

This feature is usually only makes sense for cases where you want to create dummy configurations of Bifröst to demonstrate some functionality, like we're utilizing it in our demonstration configurations: [contrib/configurations/dummy-windows.yaml](<<asset_url("contrib/configurations/dummy-windows.yaml")>>).


## Configuration {: #configuration}

<<property("type", "Environment Type", default="dummy", required=True)>>
Has to be set to `dummy` to enable the dummy environment.

<<property("banner", "string", template_context="../context/authorization.md", default="")>>
Will be displayed to the user upon connection to its environment.

<h4 id="property-banner-examples">Examples</h4>

1. If [simple user](../authorization/simple.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.entry.name}}!\n"
   ```
2. If [users authorized via OIDC](../authorization/oidc.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

<<property("exitCode", "int64", template_context="../context/authorization.md", default=0)>>
After [`banner`](#property-banner) was printed to the user, the environment will exit with this code.

### Examples {: #examples}

1. Simple:
   ```yaml
   type: simple
   ```
2. With message:
   ```yaml
   type: simple
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
