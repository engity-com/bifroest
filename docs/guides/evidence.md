---
description: Configure encrypted audit and Recording evidence, pin producer trust and verify or replay it on an administrator's workstation.
---

# Verify encrypted evidence on a workstation

This example creates encrypted audit events and Recordings on a Linux Bifröst host, then verifies and exports them on an administrator's workstation. The server receives the recipient's **public** key. The private decryption key and plaintext exports stay on the workstation.

The management login uses a separate SSH identity and trusted host key as in [the remote-management guide](management.md). Use a **new, empty** `evidence` journal and Recording directory for this example. Existing histories cannot switch encryption recipient in place.

## Examples

### Configure the recipient and server

1. On the trusted verification workstation, prepare private directories `/srv/audit-keys` and `/srv/audit-evidence`, owned by the intended verification operator. Have the workstation administrator provision them if necessary. Create a dedicated recipient key pair as that operator:

    ```shell title="Verification workstation"
    bifroest key generate \
      --identityFile /srv/audit-keys/recipient-key \
      --publicFile /srv/audit-keys/recipient-key.pub
    ```

2. Transfer **only** `recipient-key.pub` to the Bifröst host as `/etc/engity/bifroest/evidence-recipient.pub`. Provision the management login's public key in `/etc/engity/bifroest/management_authorized_keys`. Neither the recipient private key nor the management login private key belongs in this server configuration.

3. Configure the evidence and administration flows:

    ```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
    auditlog:
      - name: evidence
        enabled: true
        identityFile: /etc/engity/bifroest/evidence-signing-key
        directory: /var/lib/engity/bifroest/evidence-audit
        encryptionPublicKeyFile: /etc/engity/bifroest/evidence-recipient.pub
        recording:
          enabled: true
          directory: /var/lib/engity/bifroest/evidence-recordings

      - name: administration
        enabled: true
        identityFile: /etc/engity/bifroest/administration-signing-key
        directory: /var/lib/engity/bifroest/administration-audit

    flows:
      - name: administration
        auditlog: administration
        requirement:
          includedRequestingName: ^management$
        authorization:
          type: simple
          entries:
            - name: management
              authorizedKeysFile: /etc/engity/bifroest/management_authorized_keys
        environment:
          type: management
          allowArtifactTransfer: true

      - name: local
        auditlog: evidence
        requirement:
          excludedRequestingName: ^management$
        authorization:
          type: local
        environment:
          type: local
          name: "{{.authorization.user.name}}"
          portForwardingAllowed: false
    ```

    `allowArtifactTransfer` grants this authorized administration flow access to original signed evidence, including any unencrypted originals. The normal CLI still requires `--with-sensitive` before displaying or exporting private content.

4. Restart Bifröst using the host's service manager. The new evidence journal stores `.beaudit`; sealed Recordings use `.becast`. The separate administration journal in this example remains unencrypted.

5. As the Bifröst service user, obtain the evidence producer ID from its **signing identity**:

    ```shell title="Bifröst host"
    bifroest audit producer-id evidence
    ```

    Transfer and retain this 64-hex value through an independently trusted channel. Keep the server's signing private key on the server; do not derive producer trust from downloaded evidence.

### Configure the verification workstation

1. Provision the trusted SSH host key and management login identity as in [the management guide](management.md#configure-remote-administration).
2. Add the producer pin and local decryption paths. Replace `PRODUCER_ID` with the independently retained ID:

    ```sshconfig title="Verification workstation: ~/.ssh/config"
    IgnoreUnknown X-*

    Host bifroest-admin
        HostName bifroest.example.org
        User management
        IdentityFile ~/.ssh/bifroest-management
        UserKnownHostsFile ~/.ssh/known_hosts
        X-ExpectedProducerId PRODUCER_ID
        X-AuditPrivateKey /srv/audit-keys/recipient-key
        X-RecordingPrivateKey /srv/audit-keys/recipient-key
    ```

    The SSH login key and recipient key have separate purposes. Both private-key paths refer to the workstation. This alias pins the producer of `evidence`; other audit logs with different signing identities need their own trusted ID or alias.

3. Generate an actual Recording through the workload flow:

    ```shell title="Workload terminal"
    ssh alice@bifroest.example.org 'printf "encrypted-recording-check\n"'
    ```

    Replace `alice` with an allowed local account.

### Verify and export audit events

1. On the workstation, verify the downloaded journal and decrypted event fields:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin audit verify evidence --require-full --format=json
    ```

    A successful result has full scope. The recipient private key is read locally and is not transmitted to the server.

2. Query a limited sensitive view, or export the journal to a protected, existing output directory:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin audit events evidence --with-sensitive --flow=local --limit=20
    bifroest @bifroest-admin audit export evidence \
      --with-sensitive \
      --output /srv/audit-evidence/events.jsonl
    ```

    The output JSONL is plaintext and unsigned. Preserve the original signed journal as evidence; an export is a derived view.

### Verify, export and replay a Recording

1. Find the sealed original:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin recording ls evidence --limit=20
    bifroest @bifroest-admin recording show evidence RECORDING_UUID
    ```

    Replace `RECORDING_UUID` with the selected ID. These metadata queries receive outer verification of encrypted Recordings and do not need to decrypt them.

2. Download and fully verify that Recording:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin recording verify evidence RECORDING_UUID --require-full
    ```

    The client checks the trusted producer and the requested Recording ID against the signed original.

3. Export its verified Cast, then inspect the export independently:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin recording export evidence RECORDING_UUID \
      --with-sensitive \
      --output /srv/audit-evidence/session.cast
    bifroest recording inspect \
      --expectedProducerId PRODUCER_ID \
      /srv/audit-evidence/session.cast
    ```

4. Or replay the selected original directly on the workstation:

    ```shell title="Verification workstation"
    bifroest @bifroest-admin recording play evidence RECORDING_UUID --with-sensitive --speed=2
    ```

    `play` outputs terminal content; `export` writes a signed asciicast file. Both fully verify the encrypted content before playback or export.

## Offline alternatives

If the verification workstation is disconnected from the server, copy a complete audit journal or a sealed Recording and use local file selectors with the same independent producer ID and recipient key. Follow [the encrypted audit-copy example](../reference/auditlog/index.md#encrypted-audit-events) or the file syntax on [`recording verify`](../reference/cli/recording/verify.md).

See [Trust and verification](../reference/cli/verification.md) for key-file permissions, evidence completeness, verification scopes and protected destinations.
