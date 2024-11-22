---
description: When using Docker environments, each user session runs in a separate Docker container.
toc_depth: 5
---

# Docker environment

When using Docker environments, each user session runs in a separate Docker container. This is in contrast to the [local environment](local.md), where each user session runs on the same host as Bifröst.

This is useful if you explicitly do not want to give users access to the host itself, but to environments where they can work with defined toolsets. This is especially true, if you want to create demo or training environments.

In another use case you can set up a [Bastion/Jump host](../../usecases.md#bastion), what allows the user to jump from one server to another network. Using different [networks](#property-networks) can be beneficial too.

## Configuration {: #configuration}

<<property("type", "Environment Type", default="docker", required=True)>>
Has to be set to `docker` to enable the docker environment.

<<property("loginAllowed", "bool", template_context="../context/authorization.md", default=True)>>
Has to be true (after being evaluated) that the user is allowed to use this environment.

<h4 id="property-loginAllowed-examples">Examples</h4>

1. Require that the existing [local user](../authorization/local.md) has the group `ssh`:
   ```yaml
   loginAllowed: |
      {{ or
          (.authorization.user.group.name | eq "ssh" )
          (.authorization.user.groups     | firstMatching `{{.name | eq "ssh"}}`)
      }}
   ```

<<property("host", "string", template_context="../context/authorization.md", default="{{ env `DOCKER_HOST` }}")>>
URL how to connect to the [API endpoint of the docker compatible daemon](https://docs.docker.com/reference/api/engine/latest/).

Accepted protocols are:

1. `http`
2. `https`
3. `tcp`
4. `unix` (only supported on unix based systems)
5. `npipe` (only supported on Windows)

If this variable is empty (which can be also the case if <code>{{ env \`DOCKER_HOST\` }}</code> evaluates to empty, because the environment variable is not set), the system specific connection will be chosen:

* Unix (such as Linux): `unix:///var/run/docker.sock`
* Windows: `npipe:////./pipe/docker_engine`

<<property("apiVersion", "string", template_context="../context/authorization.md", default="{{ env `DOCKER_API_VERSION` }}")>>
Defines which version of Docker API should be chosen for communication. In doubt leave this blank.

<<property("certPath", "File path", "../data-type.md#file-path", template_context="../context/authorization.md", default="{{ env `DOCKER_CERT_PATH` }}")>>
Is a directory which should contain the following files:

* `key.pem`: Private key Bifröst should connect to the Docker API with.
* `cert.pem` Certificate Bifröst should present when connect to the Docker API.
* `ca.pem`: Certificate authorities to check the certificate of the Docker API Host against.

If this variable is empty (which can be also the case if <code>{{ env \`DOCKER_CERT_PATH\` }}</code> evaluates to empty) and [`tlsVerify`](#property-tlsVerify) is set to `false`, all Docker API Hosts are accepted.

<<property("tlsVerify", "bool", template_context="../context/authorization.md", default="{{ env `DOCKER_TLS_VERIFY` | ne `` }}")>>
If this variable is `false` (which can be also the case if <code>{{ env \`DOCKER_TLS_VERIFY\` }}</code> evaluates to empty), all Docker API Hosts are accepted.

!!! danger
     Setting this to `false` is only recommend, if connecting to the local socket connection (on the same machine - see [`host`'s default behavior](#property-host)).

<<property("image", "string", template_context="../context/authorization.md", default="alpine")>>
Which OCI/Docker image should be used for this environment.

Everything available within this image will be also available to the user who is connecting to the container using this image. Therefore, you should consider to creating your custom images if you need additional features like [`kubectl`](https://kubernetes.io/docs/reference/kubectl/), [`skopeo`](https://github.com/containers/skopeo), ... and use this one here.

This image needs to contain a valid [shell executable](#property-shellCommand).

[`ENTRYPOINT`](https://docs.docker.com/reference/dockerfile/#entrypoint) and [`CMD`](https://docs.docker.com/reference/dockerfile/#cmd) settings of the image will be ignored.

<<property("imagePullPolicy", "Pull Policy", "../data-type.md#pull-policy", template_context="../context/authorization.md", default="ifAbsent")>>
Defines what should happen if the container starts with the required image of the container.

If the image needs to be pulled, it will trigger the [`image-pull` preparation process](#preparationProcess-pull-image).

<<property("imagePullCredentials", "Docker Pull Credentials", "../data-type.md#docker-pull-credentials", template_context="../context/authorization.md")>>
Defines credentials which should be used to pull the defined [`image`](#property-image).

<h4 id="property-imagePullCredentials-examples">Examples</h4>

1. Using direct json:
   ```yaml
   imagePullCredentials: |
    {"username":"foo","password":"bar"}
   ```
2. Using base64 URL encoded json:
   ```yaml
   imagePullCredentials: |
    eyJ1c2VybmFtZSI6ImZvbyIsInBhc3N3b3JkIjoiYmFyIn0
   ```
3. Using content from file:
   ```yaml
   imagePullCredentials: "{{ file `/etc/engity/bifroest/secrets/my-great-secret` }}"
   ```
4. Using content from environment variable:
   ```yaml
   imagePullCredentials: "{{ env `MY_GREAT_SECRET` }}"
   ```

<<property("networks", array_ref("string"), template_context="../context/authorization.md", default=["default"])>>
Defines the container networks this container should be connected to.

Empty always defaults to `["default"]`.

!!! note
     As long as [`impPublishHost`](#property-impPublishHost) isn't set, the **first** network should be always reachable by Bifröst itself. This can be either the case if Bifröst itself runs inside of Docker (Bifröst in Docker) or it runs on the host machine and there is a valid route (which is the default Linux native, but not on Docker/Podman for Desktop).

<<property("volumes", array_ref("string"), template_context="../context/authorization.md")>>
Defines which volumes should be mounted into the container. Each entry is an individual mount statement.

This is the equivalent of `-v`/`--volume` flag of Docker. See [Bind mounts documentation of Docker](https://docs.docker.com/engine/storage/volumes/) about the syntax of these entries.

We recommend to use [`mounts`](#property-mounts) instead, because it is easier to understand. `volumes` is the older version of the notation and known by experienced users.

<<property("mounts", array_ref("string"), template_context="../context/authorization.md")>>
Defines which volumes should be mounted into the container. Each entry is an individual mount statement.

This is the equivalent of `--mount` flag of Docker. See [Bind mounts documentation of Docker](https://docs.docker.com/engine/storage/volumes/) about the syntax of these entries.

<<property("capabilities", array_ref("string"), template_context="../context/authorization.md")>>
List of Unix kernel capabilities to be added to the container. This enables a more fine-grained version in contrast to give all capabilities to the container with [`privileged`](#property-privileged) = `true`.

Does only work on Unix based systems.

<<property("privileged", "bool", template_context="../context/authorization.md", default=False)>>
If this is set to `true` this container will have all capabilities of the system.

!!! danger
     Only enable this feature if you really need this, and you know what you're doing.

<<property("dnsServers", array_ref("string"), template_context="../context/authorization.md")>>
Defines a list of external DNS server the container should use.

<<property("dnsSearch", array_ref("string"), template_context="../context/authorization.md")>>
Defines custom DNS search domains for the container.

<<property("shellCommand", array_ref("string"), template_context="../context/authorization.md", default="<os specific>")>>
The shell which should be used to execute the user into.

If not defined, the following command will be used:

* Linux: `["/bin/sh"]`
* Windows: `["C:\WINDOWS\system32\cmd.exe"]`

<<property("execCommand", array_ref("string"), template_context="../context/authorization.md", default="<os specific>")>>
If execute is used, this is the command prefix which will used for the command.

If not defined, the following command will be used:

* Linux: `["/bin/sh", "-c"]`
* Windows: `["C:\WINDOWS\system32\cmd.exe", "/C"]`

<<property("sftpCommand", array_ref("string"), template_context="../context/authorization.md", default="<bifroest sftp-server>")>>
Defines the sftp server command which should be used. Usually you should not be required to modify this, because by default Bifröst is handling this by itself.

<<property("directory", "File Path", "../data-type.md#file-path", template_context="../context/authorization.md")>>
Defines the working directory of the initial process inside the container for each execution.

If not defined the value [`WORKDIR`](https://docs.docker.com/reference/dockerfile/#workdir) will be used. If this is absent it defaults to: `/`.

<<property("user", "string", template_context="../context/authorization.md")>>
Defines the user will run with inside the container.

If not defined the value [`USER`](https://docs.docker.com/reference/dockerfile/#user) will be used. If this is absent it defaults to: `root`.

<<property("banner", "string", template_context="../context/authorization.md", default="")>>
Will be displayed to the user upon connection to its environment.

<h4 id="property-banner-examples">Examples</h4>

1. If [local user](../authorization/local.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.user.name}}!\n"
   ```
2. If [users authorized via OIDC](../authorization/oidc.md) is used, show its name in a message:
   ```yaml
   banner: "Hello, {{.authorization.idToken.name}}!\n"
   ```

<<property("portForwardingAllowed", "bool", template_context="../context/authorization.md", default=True)>>
If `true`, users are allowed to use SSH's port forwarding mechanism.

<<property("impPublishHost", "string", template_context="../context/authorization.md")>>
If this property is set, the port of the IMP process will be not just exposed on the container network, but also on this host.

At this address Bifröst will then connect to the IMP process inside the container.

!!! warning
     To set this property makes only sense as long you have a firewall in place, which prevents external attackers to connect to the host ports, and you have no other choice. Usually Bifröst can connect via the container networks to IMP directly (see [`networks`](#property-networks)).

This is usually required, if you run Bifröst on a Docker/Podman for Desktop installation (such as on Windows or macOS) where the Docker daemon does not run on the host directly, but inside a virtual machine.

<<property("cleanOrphan", "bool", template_context="../context/container.md", default=True)>>
While the [housekeeping iterations](../housekeeping.md) this environment will look for containers that can be inspected by its docker daemon connection if there is any container that does not belong to any flow of this Bifröst instance.

This is useful to clean up old containers which are leftovers after you have changed the configuration of Bifröst.

!!! warning
     If multiple Bifröst installations are using the same Docker host, this should be disabled. Otherwise, each instance is removing the container of the other instance.

## Preparation Processes {: #preparationProcesses }

If events about preparation processes are emitted by this environment, they are picked up by connections (like [SSH](../connection/ssh.md#preparationMessages)) and handled.

The docker environment emits the following processes:

### `pull-image` {: #preparationProcess-pull-image }

In cases an [image](#property-image) needs to be pulled, either it does not exist or [`imagePullPolicy`](#property-imagePullPolicy) is to [`always`](../data-type.md#pull-policy), the image pull process starts. As this will block the user interaction with its session, this process event is emitted. It makes it possible to show the progress of download to the user.

#### Properties

<<property("image", "string", id_prefix="preparationProcess-pull-image-", heading=5)>>
Holds the tag of the image to be downloaded.


## Examples {: #examples}

1. Simple:
   ```yaml
   type: docker
   ```
2. With ubuntu image:
   ```yaml
   type: docker
   image: ubuntu
   ## Using /bin/bash instead of /bin/sh,
   ## because it does exist in the image
   shellCommand: [/bin/bash]
   execCommand: [/bin/bash, -c]

   ## Only allow login if the OIDC's groups has "my-great-group-uuid"
   ## ...and the tid (tenant ID) is "my-great-tenant-uuid"
   loginAllowed: |
       {{ and
         (.authorization.idToken.groups | has "my-great-group-uuid")
         (.authorization.idToken.tid    | eq  "my-great-tenant-uuid")
       }}
   ```
3. Using my own registry with secret from file:
   ```yaml
   type: docker
   image: my.own.registry.com/foo/bar
   ## Using the pull credentials, which are stored inside:
   ## /etc/engity/bifroest/secrets/my.own.registry.com
   imagePullCredentials: "{{ file `/etc/engity/bifroest/secrets/my.own.registry.com` }}"
   ```
4. Using my own registry with secret from environment variable:
   ```yaml
   type: docker
   image: my.own.registry.com/foo/bar
   ## Using the pull credentials, which are stored inside
   ## MY_GREAT_SECRET environment variable
   imagePullCredentials: "{{ env `MY_GREAT_SECRET` }}"
   ```

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
