---
toc_depth: 2
description: "Bifröst is very flexible in its configuration (see configuration documentation). Here are some use cases that can be fulfilled by it:"
---
# Use cases

Bifröst can combine SSH authorization with different session environments. The following examples illustrate configurations for specific access problems; their security properties depend on the identity provider, session settings, target permissions and deployment.

1. [Off-board users by changing access at the identity provider](#offboard)
2. [On-board users with an identity provider](#onboard)
3. [Bastion Host / Jump Host](#bastion)
4. [Access Kubernetes clusters without publicly exposing their APIs](#kubernetes-firewall)
5. [Isolated Demo/Training environments](#demos)
6. [Different rules for different user groups per host](#multi-environment)
7. [Migrating from sshd](#drop-in-replacement)

!!! tip

    [Session recording](reference/auditlog/recording.md) can preserve signed terminal output, but not raw keyboard input or SFTP/forwarding payloads. An [SSH environment](reference/environment/ssh.md) can connect to a target server with a separate authentication step; it does not transparently forward arbitrary SSH requests.

## Off-board users via an identity provider {: #offboard}

### Problem

1. Assume you're part of an organization.
2. Assume this organization has more than _just_ 10 people who might be able to access SSH resources.
3. Assume you've to off-board an employee, now.
4. Assume it is your job to make sure that this employee cannot do any harm to the organization, because the machines the user is currently on are critical to the technical security of the organization.

In cases of SSH servers, this often results in going through all servers and either:

* Change the passwords,
* Remove dedicated users,
* Remove user's public keys (if you can find out who it is 🤯),
* or change the [Ansible](https://www.ansible.com/) or [Puppet](https://www.puppet.com/) configuration and apply it on every machine.

How do you stop new SSH access without updating credentials on every host? How do you check for existing sessions that must be terminated separately?

### Solution

#### Don't ...
1. ... share passwords of shared users or even the `root` user.
2. ... store unmanaged public keys on shared accounts without a revocation process.

#### Do
Use the [OpenID Connect authorization](reference/authorization/oidc.md).

For a new OIDC Device Authorization, Bifröst relies on your [Identity Provider (IdP)](https://openid.net/developers/how-connect-works/) and the configured access rules. Revocation timing depends on the IdP, token validity and session settings. A remembered SSH key, an existing session or an already authenticated [SSH target transport](reference/environment/ssh.md#certificate) is not necessarily terminated when access changes at the IdP. Plan separate session termination and a test of your actual off-boarding requirements; **there is no general 15-minute guarantee**.

IdP-managed access can reduce the need to update credentials on each host, but does not replace checking active connections and other credential paths.

Account, file and process cleanup depends on the chosen [environment](reference/environment/index.md) and explicit policies; it is not a universal default.

## On-board users via an identity provider {: #onboard}

This is the counterpart to [off-boarding users](#offboard), but the IdP, environment and target permissions must all allow the new access.

### Problem

1. Assume you're part of an organization.
2. Assume this organization has more than _just_ 10 people who might be able to access SSH resources.
3. Assume you need to on-board an employee immediately.
4. Assume you have to ensure that this employee can access all services with no delay.

In case of SSH servers, this often results in going through all servers and either:

* Share the server shared-user passwords,
* Add user's public key to a shared user,
* Add a dedicated user (with password or authorized key),
* or changing the [Ansible](https://www.ansible.com/) or [Puppet](https://www.puppet.com/) configuration and apply it at every machine.

How can this be done quickly AND NOT in days or weeks?<br>
Often admins have to ask themselves: "Did I really give them access everywhere?"

### Solution

Use [OIDC authorization](reference/authorization/oidc.md) with a configured [IdP](https://openid.net/developers/how-connect-works/) to authenticate the user. A Docker or Kubernetes session does not require a matching local host account; a [local environment](reference/environment/local.md) needs an existing account or explicit provisioning settings.

Check the permissions of the selected environment and any downstream services separately.

Resource creation depends on the [environment](reference/environment/index.md) and its configuration; it is not a universal default.

## Bastion Host / Jump Host {: #bastion}

### Problem

1. Assume you have to manage resources.
2. These resources are not directly accessible to you. They are protected within other networks to which you have no direct access, for example a service inside an [AWS private VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html).
3. You have to manage that service.

The following cases are usually used:

* You need to start a VPN connection with a VPN server to get a direct connection to this network. Either you have to deal with quirky VPN desktop client software or the SSO isn't working (which might only make sense for small organizations).
* There is a [bastion host](https://en.wikipedia.org/wiki/Bastion_host) in-place, based on [OpenSSH sshd](https://man.openbsd.org/sshd.8) which will run into [on-boarding](#onboard) and [off-boarding](#offboard) issues.

### Solution

1. Set up a bastion host, either:
    1. Inside the private network itself (in case of [AWS a dedicated EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html) for example of [instance-type `t2.micro`](https://aws.amazon.com/ec2/instance-types/))
    2. or outside the network with a fixed VPN connection to get inside the private network.
2. Configure an appropriate [authorization](reference/authorization/index.md), for example [OpenID Connect](reference/authorization/oidc.md), and review session reuse and revocation behavior.
3. Choose the [Docker environment](reference/environment/docker.md) when a container is appropriate. Isolation depends on privileges, mounted sockets/volumes and runtime access; it does not by itself guarantee the security of the host.

## Access Kubernetes clusters without publicly exposing their APIs {: #kubernetes-firewall}

### Problem

1. Assume you have one or more Kubernetes clusters.
2. There kubernetes clusters should be accessed by your developers and/or support agents to do development and debugging work.
3. The people who should access this can be located inside the office (with protected networks) but also in untrusted environments like working from home.

Usually, you either make the Kubernetes cluster's API directly accessible over the internet and secure them with (hopefully) secure secrets or shield them behind firewalls. In these cases every person who wants to access the cluster API then has to use a VPN software to access the cluster's API which also introduce other issues in usability, costs and complexity.

### Solution

1. Have a Bifröst instance inside your protected network, which port 22 is exposed to the internet.
2. Protect the access with every mechanism you like [OpenID Connect](reference/authorization/oidc.md).
3. Pick an OCI/Docker image which holds [kubectl](https://kubernetes.io/docs/reference/kubectl/).
4. Configure the [kubernetes environment](reference/environment/kubernetes.md) with a [kubeconfig](reference/environment/kubernetes.md#property-config) which is able to access the Kubernetes cluster inside your network.

As a result your people can use a standard SSH client with [OpenID Connect](reference/authorization/oidc.md) (including a browser verification step) to access a kubectl instance without exposing the cluster API directly to the public internet. The kubeconfig and Pod permissions still determine what they can do.

As a plus, the users accessing this instance have easier access to the resources like databases and rest APIs inside Kubernetes, because they can directly use the cluster internal domain names, instance `kubectl port-forward`.

## Isolated Demo/Training environments {: #demos }

### Problem

1. Assume you want to show how your software can be used (demonstration) or you want to create training sessions for users.
2. You need an environment where your users can easily have command interaction with.
3. Each user needs a dedicated and isolated environment.
4. You want to provide your own set of tools within these environments.

### Solution

1. Choose your favorite [authorization mechanism](reference/authorization/index.md), such as:
    1. [OpenID Connect](reference/authorization/oidc.md) to ensure, that only users are already registered at your application are able to connect to your service or even using public social accounts like [GitHub](https://docs.github.com/v3/oauth) or [Google](https://developers.google.com/identity/openid-connect/openid-connect) to freely connect to your service.
    2. Maybe you want to use [fixed passwords](reference/authorization/simple.md).
    3. :material-alert-octagon:{: .warning } Disable any kind of password request, which is only recommended for these kinds of purposes, nothing else. In this case, you can use the [none authorization](reference/authorization/none.md).
2. Create an OCI/Docker image with the applications you want to show.
3. Configure the [kubernetes environment](reference/environment/kubernetes.md) or the [docker environment](reference/environment/docker.md) with [a reference to your own image](reference/environment/docker.md#property-image).

## Different rules for different user groups per host {: #multi-environment}

### Problem

1. Assume you have an SSH server.
2. Different users should be authorized differently.
3. Different users should run in different [environments](reference/environment/index.md) (one in a local environment with permission A, another with permission B, and a third user in a remote environment).

Different rules can also be implemented with other SSH configurations or access platforms; Bifröst expresses the authorization and environment choice through [flows](reference/flow.md).

### Solution

Use Bifröst with multiple configured [flows](reference/flow.md). Each flow can handle different authorizations and environments.

## Migrating from sshd {: #drop-in-replacement}

For local-account SSH access, use the << asset_link("contrib/configurations/on-host.yaml", "host configuration") >> and [installation guide](setup/on-host.md). Bifröst uses port 22, so stop the previous SSH server before starting it.

Test your particular `sshd` configuration: Bifröst does not implement every OpenSSH extension or [`authorized_keys` option](reference/data-type.md#authorized-keys), such as `no-touch-required`.


## More topics
* [Configuration](reference/configuration.md)
* [Features](index.md#features)
