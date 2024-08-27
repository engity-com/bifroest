---
description: A Local environment is executed on the host itself (same host where Bifröst is running).
toc_depth: 4
---

# Local environment

A Local environment is executed on the host itself (same host where Bifröst is running).

Currently, we have different variants, different by the host operating system which is executing the environment.

Type identifier is `local`.

## Linux

The Linux variant is only supported by Linux based operating systems.

It can run as the Bifröst user itself, but can also [impersonate](https://en.wiktionary.org/wiki/impersonate) as another user.

### User requirement {: #linux-user-requirement}

Users have to fulfill the defined requirements ([`name`](#linux-property-name), [`displayName`](#linux-property-displayName), [`uid`](#linux-property-uid), [`group`](#linux-property-group), [`groups`](#linux-property-groups), [`shell`](#linux-property-shell), [`homeDir`](#linux-property-homeDir) and [`skel`](#linux-property-skel)).

If a user does not fulfill this requirement it is not eligible for the environment. The environment **can** create a user ([`createIfAbsent`](#linux-property-createIfAbsent) = `true`) or even update an existing one ([`updateIfDifferent`](#linux-property-updateIfDifferent) = `true`) to match this requirement. This makes not a lot of sense for [local users](../authorization/local.md); but a lot of sense for [users authorized via OIDC](../authorization/oidc.md) - which usually does not exist locally.

See the evaluation matrix of [`createIfAbsent`](#linux-property-createIfAbsent-evaluation) and [`updateIfDifferent`](#linux-property-updateIfDifferent-evaluation) to see the actual reactions of the local environment per users requirement evaluation state.

### Configuration {: #linux-configuration}

<<property_with_holder("loginAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'true', False, "linux-", 4)>>
Has to be true (after being evaluated) that the user is allowed to use this environment.

##### Examples {: #linux-property-loginAllowed-examples}

1. Require that the existing [local user](../authorization/local.md) has the group `ssh`:
   ```yaml
   loginAllowed: |
      {{ or
          (.authorization.user.group.name | eq "ssh" )
          (.authorization.user.groups     | firstMatching `{{.name | eq "ssh"}}`)
      }}
   ```

2. Require that [the user authorized via OIDC](../authorization/oidc.md) has in the group `my-great-group-uuid` and the tenant ID (`tid`) in this OIDC ID token:
   ```yaml
   loginAllowed: |
      {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
      }}
   ```

<<property_with_holder("name", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", None, False, "linux-", 4, "linux-user-requirement")>>
The _username_ the user should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-property-name-examples}
1. Use the name of the [local user](../authorization/local.md):
   ```yaml
   name: "{{.authorization.user.name}}"
   ```
2. Use the email address of [the user authorized via OIDC](../authorization/oidc.md):
   ```yaml
   name: "{{.authorization.idToken.email}}"
   ```
3. Always use `foobar`:
   ```yaml
   name: "foobar"
   ```

<<property_with_holder("displayName", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", None, False, "linux-", 4, "linux-user-requirement")>>
The display name (or _title_ or [_GECOS_](https://en.wikipedia.org/wiki/Gecos_field)) the user should have.

##### Examples {: #linux-property-name-examples}
1. In case of [local user](../authorization/local.md) should be never be defined.
2. Use the email address of [the user authorized via OIDC](../authorization/oidc.md):
   ```yaml
   displayName: "{{.authorization.idToken.name}}"
   ```
3. Always use `Foobar`:
   ```yaml
   displayName: "Foobar"
   ```

<<property_with_holder("uid", "Uint32 Template", "../templating/index.md#uint32", "Authorization", "../context/authorization.md", None, False, "linux-", 4, "linux-user-requirement")>>
The [_UID_ (user identifier)](https://en.wikipedia.org/wiki/User_identifier) the user should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-property-uid-examples}
1. Use the name of the [local user](../authorization/local.md):
   ```yaml
   uid: "{{.authorization.user.uid}}"
   ```
2. In case of [users authorized via OIDC](../authorization/oidc.md) this should usually not be defined.
3. Always use `123`:
   ```yaml
   uid: 123
   ```

<<property("group", "Group", "#linux-group", None, False, "linux-", 4, "linux-user-requirement")>>
The primary group the user should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-property-group-examples}
1. If [local user](../authorization/local.md) is used, this should usually not be defined.
2. Assign always group with name `oidc` in case of [users authorized via OIDC](../authorization/oidc.md):
   ```yaml
   group:
     name: "oidc"
   ```

<<property_with_holder("groups", "Array", None, "Group", "#linux-group", None, False, "linux-", 4, "linux-user-requirement")>>
The groups (do not confuse with the [primary group](#linux-property-group)) the user should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-property-groups-examples}
1. If [local user](../authorization/local.md) is used, this should usually not be defined.
2. Assign always group with name `oidc` in case of [users authorized via OIDC](../authorization/oidc.md):
   ```yaml
   groups:
     - name: "oidc"
   ```

<<property_with_holder("shell", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '"/bin/sh"', False, "linux-", 4, "linux-user-requirement")>>
The [shell](https://en.wikipedia.org/wiki/Shell_(computing)) the user should have. If not defined means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

<<property_with_holder("homeDir", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '"/home/<user.name>"', False, "linux-", 4, "linux-user-requirement")>>
The home directory the user should have. If not defined means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

<<property_with_holder("skel", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '"/etc/skel"', False, "linux-", 4, "linux-user-requirement")>>
Is a directory on the Bifröst hosts where a user that needs to be created, will receive its initial files of its [home directory](#linux-property-homeDir) from (= user's home skeleton/template directory).

<<property_with_holder("createIfAbsent", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'false', False, "linux-", 4)>>
Will create the local user if it does not exist to match the provided requirements (see below). If this property is `false` the user has to exist, otherwise the execution will fail and the connection will be closed instantly.

This property (together with [`updateIfDifferent`](#linux-property-updateIfDifferent)) should be `true` if you're using authorizations like [OIDC](../authorization/oidc.md), where the user is not expected to exist locally, and you don't want to create each user, individually.

##### Evaluation {: #linux-property-createIfAbsent-evaluation}
| [`createIfAbsent`](#linux-property-createIfAbsent) | = `false`  | = `true` |
| - | - | - |
| Exists and matches | :octicons-check-circle-24: Accepted | :octicons-check-circle-24: Accepted |
| Exists, but does not match | _Does not apply_ | _Does not apply_ |
| Does not exist | :octicons-x-circle-24: Rejected | :octicons-check-circle-24: Created and accepted |

<<property_with_holder("updateIfDifferent", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'false', False, "linux-", 4)>>
If an existing user does not match the provided requirements (see below) and this property is `true`, this user will be adjusted to match the requirements.

This property (together with [`createIfAbsent`](#linux-property-createIfAbsent)) should be `true` if you're using authorizations like [OIDC](../authorization/oidc.md), where the user is not expected to exist locally, and you don't want to create each user, individually.

##### Evaluation {: #linux-property-updateIfDifferent-evaluation}
| [`updateIfDifferent`](#linux-property-updateIfDifferent) | = `false`  | = `true` |
| - | - | - |
| Exists and matches | :octicons-check-circle-24: Accepted | :octicons-check-circle-24: Accepted |
| Exists, but does not match | :octicons-x-circle-24: Rejected | :octicons-check-circle-24: Created and accepted |
| Does not exist | _Does not apply_ | _Does not apply_ |

<<property_with_holder("banner", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '""', False, "linux-", 4)>>
Will be displayed to the user upon connection to its environment.

##### Examples {: #linux-property-banner-examples}
1. If [local user](../authorization/local.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.user.name}}!\n"
   ```
2. If [users authorized via OIDC](../authorization/oidc.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

<<property_with_holder("portForwardingAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'true', False, "linux-", 4)>>
If `true`, users are allowed to use SSH's port forwarding mechanism.

<<property("dispose", "Dispose", "#linux-dispose", None, False, "linux-", 4)>>
Defines what should happen if an environment will be disposed.

### Examples {: #linux-examples}

1. Use existing UNIX user:
   ```yaml
   type: local
   name: "{{.authorization.user.name}}"
   ```
2. OIDC - create/modify user if absent/different and cleanup automatically:
   ```yaml
   type: local

   ## Ensure users get created/modified if absent/different...
   createIfAbsent: true
   updateIfDifferent: true

   ## Use the email address of the OIDC's ID token
   name: "{{.authorization.idToken.email}}"

   ## Use the display name of the OIDC's ID token
   displayName: "{{.authorization.idToken.name}}"

   groups:
     ## Ensure user has always the group `oidc` assigned for better access control
     ## on the host itself.
     - name: oidc

   shell: "/bin/bash"

   ## Only allow login if the OIDC's groups has "my-great-group-uuid"
   ## ...and the tid (tenant ID) is "my-great-tenant-uuid"
   loginAllowed: |
       {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
       }}
   ```
### Group {: #linux-group}

<<property_with_holder("name", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", None, False, "linux-group-", 4, "linux-user-requirement")>>
The _name_ the group should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-group-property-name-examples}

1. In case of [local user](../authorization/local.md) this should usually not be used.
2. Use the email address of [the user authorized via OIDC](../authorization/oidc.md) always set the name `oidc`:
   ```yaml
   name: "oidc"
   ```

<<property_with_holder("gid", "Uint32 Template", "../templating/index.md#uint32", "Authorization", "../context/authorization.md", None, False, "linux-group-", 4, "linux-user-requirement")>>
The _GID_ (group identifier) the group should have. Empty means this requirement will not be evaluated or not applied (in case of creation/modification of a user).

##### Examples {: #linux-group-property-gid-examples}

1. Always use `123`
   ```yaml
   name: 123
   ```

### Dispose {: #linux-dispose}

Defines the behavior of an environment on disposal (cleanup).

<<property_with_holder("deleteManagedUser", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", "true", False, "linux-dispose-", 4)>>
If `true` the environment will also delete users, created/managed by it. Usually, if [`createIfAbsent`](#linux-property-createIfAbsent) and [`updateIfDifferent`](#linux-property-updateIfDifferent) is both `false` this has no effect.

<<property_with_holder("deleteManagedUserHomeDir", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", "true", False, "linux-dispose-", 4)>>
In combination with [`deleteManagedUser`](#linux-dispose-property-deleteManagedUser), if `true` the environment will **also** delete the user's home directory.

<<property_with_holder("killManagedUserProcesses", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", "true", False, "linux-dispose-", 4)>>
In combination with [`deleteManagedUser`](#linux-dispose-property-deleteManagedUser), if `true` the environment will **also** kill **all** user's running processes.

## Windows

The Windows variant is only supported by Windows 7+ based operating systems.

!!! warning
In contrast to [Linux](#linux) variant this variant **CANNOT** [impersonate](https://en.wiktionary.org/wiki/impersonate). As a consequence each user executes always as the user the process of Bifröst itself runs with.

    Impersonating on a Windows machine requires either full credentials (password) or another running process the session tokens can be cloned from. As both conflicts how we intent Bifröst should work, both solutions leaves a lot of use-cases behind and it very "hacky" we decided to stay with the simple approach.

### Configuration {: #windows-configuration}

<<property_with_holder("loginAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'true', False, "windows-", 4)>>
Has to be true (after being evaluated) that the user is allowed to use this environment.

##### Examples {: #windows-property-loginAllowed-examples}

1. Require that [the user authorized via OIDC](../authorization/oidc.md) has in the group `my-great-group-uuid` and the tenant ID (`tid`) in this OIDC ID token:
   ```yaml
   loginAllowed: |
      {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
      }}
   ```
<<property_with_holder("banner", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '""', False, "windows-", 4)>>
Will be displayed to the user upon connection to its environment.

##### Examples {: #windows-property-banner-examples}
1. If [users authorized via OIDC](../authorization/oidc.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

<<property_with_holder("shellCommand", "Strings Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '[ "C:\\\\WINDOWS\\\\system32\\\\cmd.exe" ]', False, "windows-", 4)>>
The shell which is used to execute the user into.

<<property_with_holder("execCommandPrefix", "Strings Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", '[ "C:\\\\WINDOWS\\\\system32\\\\cmd.exe", "/C" ]', False, "windows-", 4)>>
The executor command prefix which is used when a user exec a command instead of executing into a shell.

<<property_with_holder("portForwardingAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", 'true', False, "windows-", 4)>>
If `true`, users are allowed to use SSH's port forwarding mechanism.

### Examples {: #windows-examples}

1. Simple:
   ```yaml
   type: local
   ```
2. OIDC:
   ```yaml
   type: local

   ## Use the PowerShell Core without banner as Shell
   shellCommand: ["pwsh.exe", "-NoLogo"]
   directory: "C:\\my\\home"

   ## Only allow login if the OIDC's groups has "my-great-group-uuid"
   ## ...and the tid (tenant ID) is "my-great-tenant-uuid"
   loginAllowed: |
       {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
       }}
   ```
