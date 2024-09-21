---
description: A Local environment is executed on the host itself (same host on which Bifröst is running).
toc_depth: 4
---

# Local environment

A local environment is executed on the host itself (same host on which Bifröst is running).

Currently, we support different variants provided by the host operating system which is executing the environment.

Type identifier is `local`.

## Linux

The Linux variant is only supported by Linux based operating systems.

It can run as the Bifröst user itself, but can also [impersonate](https://en.wiktionary.org/wiki/impersonate) another user.

!!! Note
    If impersonating another user Bifröst is running at, root permissions are required.

### User requirement {: #linux-user-requirement}

Users have to fulfill the defined requirements ([`name`](#linux-property-name), [`displayName`](#linux-property-displayName), [`uid`](#linux-property-uid), [`group`](#linux-property-group), [`groups`](#linux-property-groups), [`shell`](#linux-property-shell), [`homeDir`](#linux-property-homeDir) and [`skel`](#linux-property-skel)).

If a user does not fulfill this requirement they are not eligible for the environment. The environment **can** creates a user ([`createIfAbsent`](#linux-property-createIfAbsent) = `true`) or even updates an existing one ([`updateIfDifferent`](#linux-property-updateIfDifferent) = `true`) to match this requirement. This does not make a lot of sense for [local users](../authorization/local.md); but for [users authorized via OIDC](../authorization/oidc.md) - which usually do not exist locally.

See the evaluation matrix of [`createIfAbsent`](#linux-property-createIfAbsent-evaluation) and [`updateIfDifferent`](#linux-property-updateIfDifferent-evaluation) to see the actual reactions of the local environment per users requirement evaluation state.

### Configuration {: #linux-configuration}

<<property("type", "Environment Type", default="local", required=True, id_prefix="linux-", heading=4)>>
Has to be set to `local` to enable the local environment.

<<property_with_holder("loginAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=True, id_prefix="linux-", heading=4)>>
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

<<property_with_holder("name", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The _username_ the user should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

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

<<property_with_holder("displayName", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The display name (or _title_ or [_GECOS_](https://en.wikipedia.org/wiki/Gecos_field)) the user should have.

##### Examples {: #linux-property-name-examples}
1. In case of [local user](../authorization/local.md) should be never be defined.
2. Use the e-mail address of [the user authorized via OIDC](../authorization/oidc.md):
   ```yaml
   displayName: "{{.authorization.idToken.name}}"
   ```
3. Always use `Foobar`:
   ```yaml
   displayName: "Foobar"
   ```

<<property_with_holder("uid", "Uint32 Template", "../templating/index.md#uint32", "Authorization", "../context/authorization.md", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The [_UID_ (user identifier)](https://en.wikipedia.org/wiki/User_identifier) the user should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

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

<<property("group", "Group", "#linux-group", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The primary group the user should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

##### Examples {: #linux-property-group-examples}
1. If [local user](../authorization/local.md) is used, this should usually not be defined.
2. Assign always group with name `oidc` in case of [users authorized via OIDC](../authorization/oidc.md):
   ```yaml
   group:
     name: "oidc"
   ```

<<property_with_holder("groups", "Array", None, "Group", "#linux-group", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The groups (do not confuse with the [primary group](#linux-property-group)) the user should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

##### Examples {: #linux-property-groups-examples}
1. If [local user](../authorization/local.md) is used, this should usually not be defined.
2. Assign always group with name `oidc` in case of [users authorized via OIDC](../authorization/oidc.md):
   ```yaml
   groups:
     - name: "oidc"
   ```

<<property_with_holder("shell", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", default="/bin/sh", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The [shell](https://en.wikipedia.org/wiki/Shell_(computing)) the user should have. Not defined means this requirement won't be evaluated or applied (in case of creation/modification of a user).

<<property_with_holder("homeDir", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", default="/home/<user.name>", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
The home directory the user should have. Not defined means this requirement won't be evaluated or applied (in case of creation/modification of a user).

<<property_with_holder("skel", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", default="/etc/skel", id_prefix="linux-", heading=4, requirement="linux-user-requirement")>>
If a new user needs to be created in a directory on the Bifröst hosts, it will receive its initial files of its [home directory](#linux-property-homeDir) from (= user's home skeleton/template directory).

<<property_with_holder("createIfAbsent", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=false, id_prefix="linux-", heading=4)>>
Will create the local user if it does not exist to match the provided requirements (see below). If this property is `false` the user has to exist, otherwise the execution will fail and the connection will be closed immediately.

This property (together with [`updateIfDifferent`](#linux-property-updateIfDifferent)) has to be `true` if you're using authorizations like [OIDC](../authorization/oidc.md), where the user is not expected to exist locally, and you don't want to create each user individually.

##### Evaluation {: #linux-property-createIfAbsent-evaluation}
| [`createIfAbsent`](#linux-property-createIfAbsent) | = `false`  | = `true` |
| - | - | - |
| Exists and matches | :octicons-check-circle-24: Accepted | :octicons-check-circle-24: Accepted |
| Exists, but does not match | _Does not apply_ | _Does not apply_ |
| Does not exist | :octicons-x-circle-24: Rejected | :octicons-check-circle-24: Created and accepted |

<<property_with_holder("updateIfDifferent", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=false, id_prefix="linux-", heading=4)>>
If an existing user does not match the provided requirements (see below) and the property is `true`, this user is asked to match the requirements.

This property (together with [`createIfAbsent`](#linux-property-createIfAbsent)) should be `true` if you're using authorizations like [OIDC](../authorization/oidc.md), where the user is not expected to exist locally and you don't want to create each user individually.

##### Evaluation {: #linux-property-updateIfDifferent-evaluation}
| [`updateIfDifferent`](#linux-property-updateIfDifferent) | = `false`  | = `true` |
| - | - | - |
| Exists and matches | :octicons-check-circle-24: Accepted | :octicons-check-circle-24: Accepted |
| Exists but does not match | :octicons-x-circle-24: Rejected | :octicons-check-circle-24: Modified and accepted |
| Does not exist | _Does not apply_ | _Does not apply_ |

<<property_with_holder("banner", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", default="", id_prefix="linux-", heading=4)>>
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

<<property_with_holder("portForwardingAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=true, id_prefix="linux-", heading=4)>>
If `true`, users are allowed to use SSH's port forwarding mechanism.

<<property("dispose", "Dispose", "#linux-dispose", id_prefix="linux-", heading=4)>>
Defines what happens if an environment is disposed.

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

<<property_with_holder("name", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", id_prefix="linux-group-", heading=4)>>
The _name_ the group should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

##### Examples {: #linux-group-property-name-examples}

1. In case of [local user](../authorization/local.md) this should usually not be used.
2. Use the email address of [the user authorized via OIDC](../authorization/oidc.md) always set the name `oidc`:
   ```yaml
   name: "oidc"
   ```

<<property_with_holder("gid", "Uint32 Template", "../templating/index.md#uint32", "Authorization", "../context/authorization.md", id_prefix="linux-group-", heading=4)>>
The _GID_ (group identifier) the group should have. Empty means this requirement won't be evaluated or applied (in case of creation/modification of a user).

##### Examples {: #linux-group-property-gid-examples}

1. Always use `123`
   ```yaml
   name: 123
   ```

### Dispose {: #linux-dispose}

Defines the behavior of an environment on disposal (cleanup).

<<property_with_holder("deleteManagedUser", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=True, id_prefix="linux-dispose-", heading=4)>>
If `true` the environment will also delete users, created/managed by it. Usually, if [`createIfAbsent`](#linux-property-createIfAbsent) and [`updateIfDifferent`](#linux-property-updateIfDifferent) is both `false` this has no effect.

<<property_with_holder("deleteManagedUserHomeDir", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=True, id_prefix="linux-dispose-", heading=4)>>
In combination with [`deleteManagedUser`](#linux-dispose-property-deleteManagedUser), if `true` the environment will **also** delete the user's home directory.

<<property_with_holder("killManagedUserProcesses", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=True, id_prefix="linux-dispose-", heading=4)>>
In combination with [`deleteManagedUser`](#linux-dispose-property-deleteManagedUser), if `true` the environment will **also** kill **all** user's running processes.

## Windows

The Windows variant is only supported by Windows 7+ based operating systems.

!!! Warning
In contrast to the [Linux](#linux) version this variant **CANNOT** [impersonate](https://en.wiktionary.org/wiki/impersonate). As a consequence, each user session always executes as the user the Bifröst process itself runs with.

    Impersonating on a Windows machine requires either full credentials (password) or another running process the session tokens can be cloned from. As both conflicts how we intend Bifröst to work, both solutions leave a lot of use-cases behind. Since it is very "hacky", we decided to stick with the simple approach.

### Configuration {: #windows-configuration}

<<property("type", "Environment Type", default="local", required=True, id_prefix="windows-", heading=4)>>
Has to be set to `local` to enable the local environment.

<<property_with_holder("loginAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", default=True, id_prefix="windows-", heading=4)>>
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
<<property_with_holder("banner", "String Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", "", id_prefix="windows-", heading=4)>>
Will be displayed to the user upon connection to its environment.

##### Examples {: #windows-property-banner-examples}
1. If [users authorized via OIDC](../authorization/oidc.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

<<property_with_holder("shellCommand", "Strings Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", ["C:\\WINDOWS\\system32\\cmd.exe"], id_prefix="windows-", heading=4)>>
The shell which is used to execute the user's session.

<<property_with_holder("execCommandPrefix", "Strings Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", [ "C:\\WINDOWS\\system32\\cmd.exe", "/C" ], id_prefix="windows-", heading=4)>>
The executor command prefix which is used when a user executes a command instead of executing into a shell.

If the user will execute `ssh foo@bar.com echo "bar"` on the host `C:\WINDOWS\system32\cmd.exe /C 'echo "bar"'` will be executed.

<<property_with_holder("directory", "Strings Template", "../templating/index.md#string", "Authorization", "../context/authorization.md", "<working directory of Bifröst>", id_prefix="windows-", heading=4)>>
The working directory in which the command will be executed in.

<<property_with_holder("portForwardingAllowed", "Bool Template", "../templating/index.md#bool", "Authorization", "../context/authorization.md", True, id_prefix="windows-", heading=4)>>
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

## Compatibility

| [`linux`/`generic`](../../setup/distribution.md#linux-generic) | [`linux`/`extended`](../../setup/distribution.md#linux-extended) | [`windows`/`generic`](../../setup/distribution.md#windows-generic) |
| - | - | - |
| <<compatibility(True)>> | <<compatibility(True)>> | <<compatibility(True)>> |
