---
description: Configure Bifröst as an SSH gateway to an existing OpenSSH server with a standard SSH client.
---

# SSH gateway to an OpenSSH server

Connect with a regular SSH client to Bifröst and open a shell on a private OpenSSH server. Bifröst authenticates the incoming connection, then makes a **separate** SSH connection to the target. It is not a transparent proxy.

This Linux example requires a running [Bifröst host service](../setup/on-host.md), an existing `target-user` account on `target.example.org`, and two distinct SSH keys: the client's key for Bifröst and Bifröst's key for the target.

## Prepare the two connections

1. Put the **client's public key** in `/etc/engity/bifroest/gateway-clients.pub` on the gateway. Keep the corresponding private key on the client.
2. On the gateway, create a separate key for the target connection:

    ```sh
    sudo bifroest key generate \
       --identityFile /etc/engity/bifroest/id_target \
       --publicFile /etc/engity/bifroest/id_target.pub
    ```

    Add `id_target.pub` to `target-user`'s `~/.ssh/authorized_keys` **on the target**. The private key stays on the gateway.
3. Verify the target host-key fingerprint through a trusted channel, then import that host key on the gateway:

    ```sh
    sudo bifroest key import host \
       --knownHostsFile /etc/engity/bifroest/target_known_hosts \
       --address target.example.org \
       --expectedFingerprint SHA256:REPLACE_WITH_VERIFIED_FINGERPRINT
    ```

    Do not use `--expectedFingerprint unknown` for a production target. The fingerprint must match the host key negotiated by this command.

## Configure Bifröst

Replace the host service's `/etc/engity/bifroest/configuration.yaml` with the following configuration, using your actual target address and account. Keep access to the gateway through another channel while changing its SSH service.

```yaml
flows:
  - name: openssh-target
    authorization:
      type: simple
      entries:
        - name: gateway
          authorizedKeysFile: /etc/engity/bifroest/gateway-clients.pub
    environment:
      type: ssh
      address: target.example.org:22
      user: target-user
      knownHostsFile: /etc/engity/bifroest/target_known_hosts
      identityFiles:
        - /etc/engity/bifroest/id_target
      portForwardingAllowed: false
```

Restart Bifröst (`sudo systemctl restart bifroest.service`), then connect from the client:

```sh
ssh -i ~/.ssh/YOUR_CLIENT_PRIVATE_KEY \
   gateway@gateway.example.org 'id -un'
```

The expected output is `target-user`. Check Bifröst's own host key with the gateway administrator on first connection; it is **not** the target's host key. No Bifröst account named `gateway` is needed: `simple` matches the incoming SSH name and its public key. If the target connection fails, first check the target account's `authorized_keys` and the verified `knownHostsFile`.

The example disables port forwarding. SFTP is allowed by default only if the target accepts it; the gateway does not forward arbitrary SSH session requests. For user certificates or Bifröst-to-Bifröst delegation, see the [SSH environment reference](../reference/environment/ssh.md).
