---
description: Export configured public SSH identities, certificate authorities and active host keys through a separate management flow.
---

# Export server public keys remotely

This Linux example configures a certificate-authenticated SSH gateway and a separate, read-only management flow. An administrator exports the gateway's existing public identities to a workstation. Private keys stay on their source machines.

Start with an installed [Bifröst host](../setup/on-host.md), separate login keys for the administrator and `alice`, and an OpenSSH target for `alice` at `target.example.org`. Obtain the target host keys through a trusted provisioning channel. The first management connection also needs an independently trusted Bifröst host-key entry; remote key export cannot establish its own initial host trust.

## Examples

### Configure the management and gateway flows

1. Provision these public files on the Bifröst host:

    | File | Initial content |
    | --- | --- |
    | `/etc/engity/bifroest/management_authorized_keys` | Administrator's public login key. |
    | `/etc/engity/bifroest/gateway-clients.pub` | Alice's public login key for Bifröst. |
    | `/etc/engity/bifroest/target_known_hosts` | Independently trusted host-key entries for `target.example.org`. |

    Make the files readable by the service user. Keep the administrator's private login key on the workstation as `~/.ssh/bifroest-management`. The target's CA configuration follows after exporting the gateway CA below.

2. Configure the Bifröst host:

    ```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
    flows:
      - name: administration
        requirement:
          includedRequestingName: ^management$
        authorization:
          type: simple
          entries:
            - name: management
              authorizedKeysFile: /etc/engity/bifroest/management_authorized_keys
        environment:
          type: management

      - name: gateway
        requirement:
          includedRequestingName: ^alice$
        authorization:
          type: simple
          entries:
            - name: alice
              authorizedKeysFile: /etc/engity/bifroest/gateway-clients.pub
        environment:
          type: ssh
          address: target.example.org
          user: alice
          knownHostsFile: /etc/engity/bifroest/target_known_hosts
          certificate:
            identityFile: /etc/engity/bifroest/gateway-subject
            authorityIdentityFile: /etc/engity/bifroest/gateway-ca
    ```

    `management` selects the administration flow, and `alice` selects the gateway. The management flow needs no optional permissions for public key exports. Alice's incoming login key, the gateway's outbound certificate CA, and target host trust have separate roles.

3. Start or restart Bifröst through the host's service manager. Startup loads the provisioned trust and ensures the configured gateway subject and CA identities. Remote exports will only use these existing keys.

4. After provisioning Bifröst's host key in the workstation's `~/.ssh/known_hosts`, add the login alias:

    ```sshconfig title="Administrator workstation: ~/.ssh/config"
    Host bifroest-admin
        HostName bifroest.example.org
        User management
        IdentityFile ~/.ssh/bifroest-management
        UserKnownHostsFile ~/.ssh/known_hosts
    ```

### Export the running server's public keys

1. Export the gateway's CA and subject public identity:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin key export ca gateway --output gateway-ca.pub
    bifroest @bifroest-admin key export public gateway --output gateway-subject.pub
    ```

    These output files are on the workstation. Provision the exported CA at the OpenSSH target to trust the gateway's outbound certificates for `alice`, following [the certificate-authentication example](../reference/environment/ssh.md#openssh-certificate-authentication). A remote export never creates or replaces a missing server key.

2. Export Bifröst's active host keys, labeling them with its externally used address:

    ```shell title="Administrator workstation"
    bifroest @bifroest-admin key export host \
      --address bifroest.example.org \
      --output bifroest-known-hosts
    ```

    Use `--force` only when replacing an existing workstation output file is intended. Server trust files are maintained through normal configuration management.

### Use a standard SSH client

1. Use the same management authorization and trusted host key with a standard SSH client:

    ```shell title="Administrator workstation"
    ssh management@bifroest.example.org 'key export ca gateway' > gateway-ca.pub
    ssh management@bifroest.example.org 'key export public gateway' > gateway-subject.pub
    ssh management@bifroest.example.org 'key export host --address=bifroest.example.org' > bifroest-known-hosts
    ```

    Supply the login identity or agent required by that SSH client. Direct SSH writes public exports to stdout; choose the workstation destination through the SSH client's output redirection.

## Next steps

* [Key reference](../reference/cli/key/index.md) documents per-command arguments and invocation modes.
* [Management permissions](../reference/environment/management.md#configuration) describes the separate access controls.
* [Bifröst delegation](../reference/authorization/bifroest.md) configures certificate trust between Bifröst instances.
