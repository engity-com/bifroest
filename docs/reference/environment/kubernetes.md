---
description: When using Kubernetes environments, each user session runs in a separate POD in a defined cluster.
toc_depth: 5
---

# Kubernetes environment

When using Kubernetes environments, each user session runs in a dedicated [Pod](https://kubernetes.io/docs/concepts/workloads/pods/) inside a defined [Kubernetes cluster](https://kubernetes.io/docs/concepts/architecture/). This is in contrast to the [local environment](local.md), where each user session runs on the same host as Bifröst.

## With Bifröst

As the resulting Pod runs inside of Kubernetes and the terminal session will be connected to this Pod, the user can access (depending on the cluster settings) access everything directly inside the cluster.

You can prepare images with all required tolls installed (like database client, [curl](https://curl.se/), ...) and can access all resource directly with the cluster internal addresses like `my-service.my-namespace` (or `my-service.my-namespace.svc.cluster.local`). Assuming at `my-service.my-namespace` is a REST service running at port `80` the following command will run out-of-the box once you connected via ssh:
```shell
curl http://my-service.my-namespace
```

The SSH-client port-forwarding, works too and even the SOCKS5 proxy, where you can call every cluster internal URL from within your desktop browser.

If there is also [kubectl](https://kubernetes.io/docs/reference/kubectl/) installed in the used image and an adequate [serviceAccount](#property-serviceAccountName) is configured, you can even use `kubectl` without any further authorizations.

This simply means: You do not need tools like `kubectl` locally installed and configured, your favorite SSH-client is enough.

## Without Bifröst

Usually there are the following scenarios used to access resources inside a kubernetes cluster:

1. Directly from the local command line via [kubectl](https://kubernetes.io/docs/reference/kubectl/) using dedicated credentials, which needs direct access to the cluster API, which may not always be desirable.
2. Using a [Bastion/Jump Host](https://en.wikipedia.org/wiki/Bastion_host) where all the stuff is already installed, as in point 1.

Or to interact with resources inside the cluster itself (like connect to a database, REST service, ...), usually the following scenarios are used:

1. Using kubectl (in any way as described before), using [port forwarding](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/).
2. Or (also with kubectl) [execute inside an existing inside the desired cluster](https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/) with all required tools installed.

## Configuration {: #configuration}

<<property("type", "Environment Type", default="kubernetes", required=True)>>
Has to be set to `kubernetes` to enable the Kubernetes environment.

<<property("config", "Kubeconfig", "../data-type.md#kubeconfig", template_context="../context/core.md")>>
Holds a [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) (in YAML format) which defines the access to the desired Kubernetes cluster.

Ensure that the used configuration points to a user/service account with sufficient permissions to get/list/watch/create/modify/delete pods, secrets (depends on the configuration of Bifröst) and namespaces (depends on the configuration of Bifröst).

If the content is explicitly set to `incluster` it assumes that Bifröst runs inside a Kubernetes Pod and a [valid service account was configured](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions), all required resources are present (`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT` environment variable, `/var/run/secrets/kubernetes.io/serviceaccount/token`, `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` and `/var/run/secrets/kubernetes.io/serviceaccount/namespace`).

<h4 id="property-config-default">Default behavior</h4>

If this property is not defined, the following steps will be evaluated:

1. If the environment variable `KUBE_CONFIG` exists, its content will be evaluated.
2. If the environment variable `KUBECONFIG` exists it should contain file names, these will be read and its content will be evaluated.
3. If the file `~/.kube/config` exists, its content will be read and its content will be evaluated.
4. If all dependencies like `incluster` exists, it will be used.
5. Fail.

<h4 id="property-config-examples">Examples</h4>

1. Using direct yaml:
   ```yaml
   config: |
        clusters:
        - cluster:
          name: my-cluster
            server: https://k8s.example.org/k8s/clusters/c-xxyyzz
        users:
        - name: my-auth
            token: foo
        current-context: my-context
        contexts:
        - context:
          name: my-context
            user: my-auth
            cluster: my-cluster
   ```
2. Using content from file:
   ```yaml
   config: "{{ file `/etc/engity/bifroest/kubernetes/my-config` }}"
   ```
3. Using content from environment variable:
   ```yaml
   config: "{{ env `MY_GREAT_CONFIG` }}"
   ```
4. Use `incluster` config:
   ```yaml
   config: "incluster"
   ```

<<property("context", "string", template_context="../context/core.md")>>
Defines which context of the [config](#property-config) should be used.

If not defined the default one of the [config](#property-config) will be used. If also there is nothing defined, this will result in an error.

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

<<property("name", "string", template_context="../context/authorization.md", default="bifroest-{{.session.id}}")>>
[Kubernetes name](https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names) of the Pod which will be created.

<<property("namespace", "string", template_context="../context/authorization.md")>>
[Kubernetes namespace](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/) where the Pod will be created inside.

If this is empty, the configured namespace of the provided [config](#property-config) will be used. If this is empty too, `default` will be used.

If the namespace does not exist, it will be created.

<<property("os", "Os", "../data-type.md#os", template_context="../context/authorization.md", default="linux")>>
Defines the operating system the resulting container should use. There are only support values supported where also a [distribution of Bifröst](../../setup/distribution.md#compatibility) in combination with the matching value of the [arch](#property-arch) property exists.

<<property("arch", "Arch", "../data-type.md#arch", template_context="../context/authorization.md", default="amd64")>>
Defines the architecture the resulting container should use. There are only support values supported where also a [distribution of Bifröst](../../setup/distribution.md#compatibility) in combination with the matching value of the [os](#property-os) property exists.

<<property("serviceAccountName", "string", template_context="../context/authorization.md", default="")>>
Is the name of the [Kubernetes Service Account](https://kubernetes.io/docs/concepts/security/service-accounts/) which should be used by the Pod will be created.

It is used to grant/restrict the direct access to the Kubernetes internal APIs, by creating [role-base access control (RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) matching the service account. For more details see [Grant ServiceAccount permissions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#service-account-permissions) of the Kubernetes documentation.

If this is configured, a [kubectl](https://kubernetes.io/docs/reference/kubectl/) installed inside the Pod's image, can access the clusters resources (following the permissions granted via RBAC).

<<property("image", "string", template_context="../context/authorization.md", default="alpine")>>
An OCI/Docker image which should be used for the container. Everything inside this image will be available to the user who is executed via SSH into this Pod's container.

There can be any public available image be used or also private images. If you're using private images, you need to provide [imagePullSecretName](#property-imagePullSecretName) and/or [imagePullCredentials](#property-imagePullCredentials). Always ensure that the image can be accessed from the Kubernetes cluster itself; Bifröst itself will not interact with this image.

<<property("imagePullPolicy", "Pull Policy", "../data-type.md#pull-policy", template_context="../context/authorization.md", default="ifAbsent")>>
Controls when the [image](#property-image) of the resulting Pod should be pulled.

<<property("imagePullSecretName", "string", template_context="../context/authorization.md")>>
If defined, this secret will be used to pull the defined [image](#property-image) from the image registry. This is usually necessary if private images are used. See [Kubernetes documentation how to pull images from private registries](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) for more information and to find out how to create such a secret.

This secret has to exist, otherwise the creation of the Pod will fail.

If [imagePullCredentials](#property-imagePullCredentials) is defined, this secret does not have to exist, it will be created, based on this property's content. If `imagePullSecretName` is empty in this case, the resulting name will be `pull-secret.<pod-name>`.

<<property("imagePullCredentials", "string", template_context="../context/authorization.md")>>
If defined, these credentials are used to pull the defined [image](#property-image) from the image registry. It will result in a [pull secret](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) which will be created with the name of [imagePullSecretName](#property-imagePullSecretName) and the content of this property.

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

<<property("readyTimeout", "Duration", "../data-type.md#duration", template_context="../context/authorization.md", default="5m")>>
Defines the maximum time the Pod is allowed to be successfully started within. If this time is passed and the Pod is not ready, it will be marked as failed and will be reported back to the user who tries to connect via SSH.

<<property("removeTimeout", "Duration", "../data-type.md#duration", default="1m")>>
Defines the maximum time the Pod is allowed to gracefully shutdown within. Longer will result in an error.

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
Defines the user which will run inside the container.

If not defined the value [`USER`](https://docs.docker.com/reference/dockerfile/#user) will be used. If this is absent it defaults to: `root`.

<<property("group", "string", template_context="../context/authorization.md")>>
Defines the group of the user which will run inside the container.

If this is absent it defaults to the group of the [user](#property-user).

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

<<property("cleanOrphan", "bool", template_context="../context/container.md", default=True)>>
While the [housekeeping iterations](../housekeeping.md) this environment will look for containers that can be inspected by its docker daemon connection if there is any container that does not belong to any flow of this Bifröst instance.

This is useful to clean up old containers which are leftovers after you have changed the configuration of Bifröst.

!!! warning
     If multiple Bifröst installations are using the same Docker host, this should be disabled. Otherwise, each instance is removing the container of the other instance.

## Preparation Processes {: #preparationProcesses }

If events about preparation processes are emitted by this environment, they are picked up by connections (like [SSH](../connection/ssh.md#preparationMessages)) and handled.

The kubernetes environment can emit the following processes:

### `create-pod` {: #preparationProcess-create-pod }

As the creation of a pod creation can take up-to some minutes, this process will be emitted. As this process does not really expose progress of downloading a required image or similar, there is currently no progress reporting supported (only a fake 0% .. 30% .. 100%).

#### Properties

<<property("name", "string", id_prefix="preparationProcess-create-pod-", heading=5)>>
Target name of the Pod. See [property name](#property-name) for more details.

<<property("namespace", "string", id_prefix="preparationProcess-create-pod-", heading=5)>>
Target namespace of the Pod. See [property namespace](#property-namespace) for more details.

<<property("image", "string", id_prefix="preparationProcess-create-pod-", heading=5)>>
Target image of the Pod. See [property image](#property-image) for more details.

### `remove-pod` {: #preparationProcess-remove-pod }

If it is required to remove an existing pod before a new will be created, this process can be made visible to the user. There is currently no progress reporting supported.

#### Properties

<<property("name", "string", id_prefix="preparationProcess-remove-pod-", heading=5)>>
Name of the existing Pod. See [property name](#property-name) for more details.

<<property("namespace", "string", id_prefix="preparationProcess-remove-pod-", heading=5)>>
Namespace of the existing Pod. See [property namespace](#property-namespace) for more details.

## Examples {: #examples}

1. Basic
    ```yaml
    type: kubernetes
    ## This will create a Kubernetes environment based on the
    ## default context, defined inside `~/.kube/config`
    ## OR the content of the environment variable KUBE_CONFIG
    ## with alpine image.
    ```

2. Explicit context
    ```yaml
    type: kubernetes
    context: "my-context"
    ## This will create a Kubernetes environment based on the
    ## context "my-context", defined inside `~/.kube/config`,
    ## with alpine image.
    ```

3. Custom kube-config
    ```yaml
    type: kubernetes
    config: "/etc/kube/my-kube-config"
    ## This will create a Kubernetes environment based on the
    ## default context of the kube config stored inside
    ## /etc/kube/my-kube-config.
    ```

4. With ubuntu image, custom shell and login restriction
    ```yaml
    type: kubernetes
    ## This will create a Kubernetes environment based on the
    ## default context, defined inside `~/.kube/config`.

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

5. Using my own registry with secret from file:
   ```yaml
   type: kubernetes
   image: my.own.registry.com/foo/bar
   ## Using the pull credentials, which are stored inside:
   ## /etc/engity/bifroest/secrets/my.own.registry.com
   imagePullCredentials: "{{ file `/etc/engity/bifroest/secrets/my.own.registry.com` }}"
   ```

6. Using my own registry with secret from environment variable:
   ```yaml
   type: kubernetes
   image: my.own.registry.com/foo/bar
   ## Using the pull credentials, which are stored inside
   ## MY_GREAT_SECRET environment variable
   imagePullCredentials: "{{ env `MY_GREAT_SECRET` }}"
   ```

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
