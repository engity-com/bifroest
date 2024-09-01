---
toc_depth: 2
description: As Bifröst is very flexible how it can be configured, here some use-cases which can be fulfilled by it.
---
# Use cases

As Bifröst is very flexible how it can be configured (see [configuration documentation](reference/configuration.md)), here some use-cases which can be fulfilled by it:

1. [**Off**-board users within 15 minutes of the organization](#offboard)
2. [**On**-board users within 15 minutes in the organization](#onboard)
3. [Bastion Host / Jump Host](#bastion)
4. [Different rules for different users per host](#multi-environment)
5. [Drop-in-Replacement](#drop-in-replacement)

!!! tip

    We're planning to also implement a [Docker](https://github.com/engity-com/bifroest/issues/11) and a [Kubernetes](https://github.com/engity-com/bifroest/issues/12) environment. This will create much more use-cases, soon. 🤠

## Off-board users within 15 minutes of the organization {:id=offboard}

### Problem

1. Assume you're part of an organization.
2. Assume this organization has more than _just_ 10 people who might be able to access SSH resources.
3. Assume you've to off-board an employee, now.
4. Assume you should ensure that this employee is unable to do harm to the organization, as the machines are crucial for the organization's technical security.

In cases of SSH servers, this often results in running through all servers and either:

* Change the passwords,
* Remove dedicated users,
* Remove user's public keys (if the command really tell you who it is 🤯),
* or change the [Ansible](https://www.ansible.com/) or [Puppet](https://www.puppet.com/) configuration apply it at every machine.

How this should be done within 15 minutes (not days or weeks)?<br>
How do you ensure you really removed this user everywhere?

### Solution

#### Don't
1. Have users installed on the systems itself.
2. Share passwords of shared users or even the `root` user.
3. Have user's public keys stored at shared users or even the `root` user.

#### Do
Use the [OpenID Connect authorization](reference/authorization/oidc.md).

As the users always authorized by your [Identity Provider (IdP)](https://openid.net/developers/how-connect-works/), and this is always evaluated when someone tries to access the service via SSH, it will also immediately reject the authorization to this service.

No need to access any of these services directly to remove/de-authorize these users.

If the [environments are configured accordingly](reference/environment/index.md) (which is the default) all user's files and processes will be removed/killed automatically, too.

## On-board users within 15 minutes in the organization {:id=onboard}

This is quite similar to [Off-board users within 15 minutes of the organization](#offboard), but obviously reverse.

### Problem

1. Assume you're part of an organization.
2. Assume this organization has more than _just_ 10 people who might be able to access SSH resources.
3. Assume you've to on-board an employee, now.
4. Assume you should ensure that this employee is ab to have access to all services, now.

In cases of SSH servers, this often results in running through all servers and either:

* Share the server shared-user passwords,
* Add user's public key to a shared user,
* Add a dedicated user (with password or authorized key),
* or change the [Ansible](https://www.ansible.com/) or [Puppet](https://www.puppet.com/) configuration apply it at every machine.

How this should be done now (not days or weeks)?<br>
"Did I really give him access everywhere?"

### Solution

Use the [OpenID Connect authorization](reference/authorization/oidc.md).

There is no need to create them somewhere on the server itself. The [OIDC authorization](reference/authorization/oidc.md) will resolve them using the configured [Identity Provider (IdP)](https://openid.net/developers/how-connect-works/) - that's it!

No need to access any of these services directly to create/authorize these users.

If the [environments are configured accordingly](reference/environment/index.md) (which is the default) all user's resources (like home directory) will be created automatically.

## Bastion Host / Jump Host {:id=bastion}

### Problem

1. Assume you've to manage resources.
2. These resources are not directly reachable for you. They are protected inside other networks, you have no direct access to. For example, you're sitting at home and there is a another service inside an [AWS private VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html).
3. You have to manage this service.

The following cases are usually used:

* You need to start a VPN connection, with an VPN server to get a direct connection to this network. Either you have to deal with quirky VPN desktop client software or SSO isn't working (which might only make sense for small organizations).
* There is a [bastion host](https://en.wikipedia.org/wiki/Bastion_host) in-place, based on [OpenSSH sshd](https://man.openbsd.org/sshd.8) which will run into [on-boarding](#onboard) and [off-boarding](#offboard) issues.

### Solution

1. Set up a bastion host either:
   1. Inside the private network itself (in case of [AWS a dedicated EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html) for example of [instance-type `t2.micro`](https://aws.amazon.com/ec2/instance-types/))
   2. or outside with a fixed VPN connection inside the private network.
2. Configure your favored [authorization](reference/authorization/index.md) (for example [OpenID Connect](reference/authorization/oidc.md) for best [on-boarding](#onboard) and [off-boarding](#offboard) experience).

## Different rules for different users per host {:id=multi-environment}

### Problem

1. Assume you have an SSH server.
2. Different users should be authorized differently.
3. Different users should be executed into different [environments](reference/environment/index.md) (the one into a local one with permission A, another one with permission B and the other one into a remote one).

This is currently not really possible, except with different [OpenSSH sshd](https://man.openbsd.org/sshd.8) setups on one host, or even different hosts or hacky [PAM](https://en.wikipedia.org/wiki/Linux_PAM) or [shell](https://en.wikipedia.org/wiki/Unix_shell) setups.

### Solution

You're using Bifröst with multiple [flows](reference/flow.md), configured. Each flow can handle different authorization and environments.

## Drop-in-Replacement {:id=drop-in-replacement}

You simply want to use something else than [OpenSSH sshd](https://man.openbsd.org/sshd.8), Bifröst will do this, too. 😉 Just use << asset_link("contrib/configurations/sshd-dropin-replacement.yaml", "this configuration") >>.


## More topics
* [Configuration](reference/configuration.md)
* [Features](index.md#features)
