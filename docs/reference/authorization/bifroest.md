---
toc_depth: 4
description: Authorize certificate-based delegation from another Bifröst instance.
---

# Bifröst authorization

Authorizes an SSH connection delegated by another Bifröst instance. This authorization accepts only OpenSSH user certificates carrying Bifröst's signed delegation evidence. Password and keyboard-interactive authentication are always rejected.

## Properties

<<property("type", "Authorization Type", default="bifroest", required=True)>>
Has to be set to `bifroest` to enable Bifröst delegation authorization.

<<property("trustedUserCAs", "Public Keys", "../data-type.md#public-keys")>>
OpenSSH public keys of the immediately upstream Bifröst certificate authorities. At least this property or [`trustedUserCAsFile`](#property-trustedUserCAsFile) is required.

<<property("trustedUserCAsFile", ref("File Path", "../data-type.md#file-path", ref("Public Keys", "../data-type.md#public-keys")))>>
Same as [`trustedUserCAs`](#property-trustedUserCAs), but loaded from one file when the authorization is initialized. Both properties can be used together. A configured file must exist and contain at least one valid public key.

<<property("audiences", "list of strings")>>
Accepted delegation audiences. If omitted, only the name of the local flow is accepted. An explicitly configured non-empty list replaces that default; an explicitly empty list is invalid.

<<property("maxCertificateValidity", "Duration", "../data-type.md#duration", default="15m")>>
Maximum interval from the evidence issuance time to the certificate's immutable `ValidBefore` boundary. Certificates exceeding this limit are rejected.

## Validation

The presented credential has to satisfy all of these conditions:

* It is a current OpenSSH user certificate signed by a configured immediately upstream CA.
* The requested SSH username is one of its principals.
* Its only critical option is `bifroest-delegation@bifroest.engity.org` with an empty value.
* It contains canonical `bifroest.authorization-evidence/v1` under `evidence-v1@bifroest.engity.org`.
* The final evidence hop matches the certificate CA, subject key, serial, key ID, validity, target user and effective forwarding capabilities.
* The final audience is accepted and the original authorization was authenticated.
* The evidence is at most 4 KiB, has at most eight hops and contains no repeated subject-key fingerprint.
* Every downstream hop can only shorten validity and remove PTY, port-forwarding or agent-forwarding capabilities.

The evidence is verified again after the SSH client proves possession of the certificate subject key. No session is created before that proof succeeds.

## Example: Entry Gateway to Target Gateway

**Bifröst A** sits between the Internet and the internal network. It authenticates `alice` with `simple`; internal **Bifröst B** is not Internet-accessible and trusts delegations from A.

1. Configure A:

    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    flows:
      - name: to-target
        authorization:
          type: simple
          entries:
            - name: alice
              password: plain:change-me
        environment:
          type: ssh
          address: target.example.org
          user: '{{ .session.created.remote.user }}'
          knownHostsFile: /etc/engity/bifroest/known_hosts
          certificate:
            audience: from-entry
            extensions:
              permit-pty: ""
              permit-port-forwarding: ""
              permit-agent-forwarding: ""
    ```

    !!! warning
         The plain password is only for this minimal example. Use a password hash or another authorization in production.

2. Configure B:
    ```yaml title="/etc/engity/bifroest/configuration.yaml"
    flows:
      - name: from-entry
        authorization:
          type: bifroest
          trustedUserCAsFile: /etc/engity/bifroest/trusted-cas
        environment:
          type: local
    ```

3. Run on B:
    ```shell
    bifroest key export host \
      --identityFile /etc/engity/bifroest/key \
      --address target.example.org
    ```
4. To trust B, run on A:
    ```shell
    echo "<output of command executed on B>" | bifroest key import host \
      --knownHostsFile /etc/engity/bifroest/known_hosts
    ```

5. Export A's CA before its first start:
    ```shell
    bifroest key export ca \
      -c /etc/engity/bifroest/configuration.yaml \
      to-target
    ```

    !!! note
         `bifroest key export ca` creates A's missing CA without creating a `.pub` companion file. The same CA is used when A starts.

6. To trust the CA of A, run on B:
    ```shell
    echo "<output of command executed on A>" | bifroest key import ca \
      --trustedCAsFile /etc/engity/bifroest/trusted-cas
    ```

7. Start B:
    ```shell
    bifroest run -c /etc/engity/bifroest/configuration.yaml
    ```

8. Start A:
    ```shell
    bifroest run -c /etc/engity/bifroest/configuration.yaml
    ```

B verifies A's CA signature, the `from-entry` audience, the signed evidence and possession of A's persistent `client-key`.

## Context

This authorization produces a context of type [Authorization Bifröst](../context/authorization.md#bifroest).

## Compatibility

| <<dist("linux")>> | <<dist("windows")>> |
| - | - |
| <<compatibility_editions(True,True,"linux")>> | <<compatibility_editions(True,None,"windows")>> |
