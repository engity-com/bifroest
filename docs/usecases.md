---
toc_depth: 2
description: "Bifröst is very flexible in its configuration (see configuration documentation). Here are some use cases that can be fulfilled by it:"
---
# Use cases

As Bifröst is very flexible on how it can be configured (see [configuration documentation](reference/configuration.md)), here are some use-cases which can be fulfilled by it:

1. [**Off**-board users within the legally binding 15 minutes timeframe of the organization](#offboard)
2. [**On**-board users within 15 minutes in the organization](#onboard)
3. [Bastion Host / Jump Host](#bastion)
4. [Different rules for different users per host](#multi-environment)
5. [Drop-in-Replacement](#drop-in-replacement)

!!! tip

    We're planning to also implement a [Docker](https://github.com/engity-com/bifroest/issues/11) and a [Kubernetes](https://github.com/engity-com/bifroest/issues/12) environment. This will create much more use-cases, soon. 🤠

## Off-board users within the legally binding 15 minutes timeframe of the organization {:id=offboard}

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

How this should be done within the legally binding 15 minutes timeframe AND NOT over days or weeks?<br>
How do you ensure you really removed this user everywhere?

### Solution

#### Don't ...
1. ... have users installed on the systems itself.
2. ... share passwords of shared users or even the `root` user.
3. ... have user's public keys stored at shared users or even the `root` user.

#### Do
Use the [OpenID Connect authorization](reference/authorization/oidc.md).

As the users are always authorized by your [Identity Provider (IdP)](https://openid.net/developers/how-connect-works/), their access rights are always evaluated when someone tries to access the service via SSH. If the IdP rejects the authorization, Bifröst will also immediately reject the authorization to this service. Depending on the residual duration of the off-token, the user rights are taken away within a maximum timeframe of 15 minutes.

There is no need to access any of these services directly to remove/de-authorize these users.

If the [environments are configured accordingly](reference/environment/index.md) (default setting) all of the user's files and processes will be removed/killed automatically, too.

## On-board users within 15 minutes in the organization {:id=onboard}

This is quite similar to [Off-board users within the legally binding 15 minutes of the organization](#offboard), but obviously reverse.

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

Use the [OpenID Connect authorization](reference/authorization/oidc.md).

There is no need to create them somewhere on the server itself. The [OIDC authorization](reference/authorization/oidc.md) will do that using the configured [Identity Provider (IdP)](https://openid.net/developers/how-connect-works/) - that's it!

There is no need to access any of these services directly to create/authorize these users.

If the [environments are configured accordingly](reference/environment/index.md) (default setting), all of the user's resources (like the home directory) will be created automatically.

## Bastion Host / Jump Host {:id=bastion}

### Problem

1. Assume you have to manage resources.
2. These resources are not directly accessible to you. They are protected within other networks to which you have no direct access. For example, you're sitting at home and there's another service inside an [AWS private VPC]. (https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html).
3. You have to manage that service.

The following cases are usually used:

* You need to start a VPN connection with a VPN server to get a direct connection to this network. Either you have to deal with quirky VPN desktop client software or the SSO isn't working (which might only make sense for small organizations).
* There is a [bastion host](https://en.wikipedia.org/wiki/Bastion_host) in-place, based on [OpenSSH sshd](https://man.openbsd.org/sshd.8) which will run into [on-boarding](#onboard) and [off-boarding](#offboard) issues.

### Solution

1. Set up a bastion host, either:
   1. Inside the private network itself (in case of [AWS a dedicated EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html) for example of [instance-type `t2.micro`](https://aws.amazon.com/ec2/instance-types/))
   2. or outside the network with a fixed VPN connection to get inside the private network.
2. Configure your preferred [authorization](reference/authorization/index.md) (for example [OpenID Connect](reference/authorization/oidc.md) for best [on-boarding](#onboard) and [off-boarding](#offboard) experience).

## Different rules for different users per host {:id=multi-environment}

### Problem

1. Assume you have an SSH server.
2. Different users should be authorized differently.
3. Different users should run in different [environments](reference/environment/index.md) (one in a local environment with permission A, another with permission B, and a third user in a remote environment).

This is almost impossible with current technologies except with different [OpenSSH sshd](https://man.openbsd.org/sshd.8) setups on a host, or even different hosts, or hacked [PAM](https://en.wikipedia.org/wiki/Linux_PAM) or [shell](https://en.wikipedia.org/wiki/Unix_shell) set-ups.

### Solution

Use Bifröst with multiple configured [flows](reference/flow.md). Each flow can handle different authorizations and environments.

## Drop-in-Replacement {:id=drop-in-replacement}

You simply want to use something else than [OpenSSH sshd](https://man.openbsd.org/sshd.8), Bifröst will do this, too. 😉 Just use << asset_link("contrib/configurations/sshd-dropin-replacement.yaml", "this configuration") >>.


## More topics
* [Configuration](reference/configuration.md)
* [Features](index.md#features)
