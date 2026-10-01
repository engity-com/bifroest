---
description: Enable signed SSH session recording and audit events in Bifröst, verify evidence and export an asciicast.
---

# Verifiable SSH session recording

Bifröst can record terminal output from SSH shell and command sessions and sign the result for later verification. This example adds an audit journal **and** recording to the [local-account host configuration](../setup/on-host.md).

Add `auditlog` at the **top level** of `/etc/engity/bifroest/configuration.yaml`, alongside `flows`:

```yaml
auditlog:
  - name: default
    enabled: true
    recording:
      enabled: true
flows:
  - name: local
    authorization:
      type: local
    environment:
      type: local
      name: "{{.authorization.user.name}}"
      portForwardingAllowed: false
```

The existing `local` flow uses `default` automatically. Restart the Bifröst service, then run a command through it:

```sh
ssh "$USER@localhost" 'printf "recording-check\n"'
```

After the command ends, look for `<recording-uuid>.bcast` under `/var/lib/engity/bifroest/recordings/sealed/`. On the Bifröst host, use that UUID to verify the signed recording and the audit journal:

```sh
sudo bifroest recording verify default YOUR_RECORDING_UUID
sudo bifroest audit verify default
```

To export it as an asciicast v3 file outside the managed repository:

```sh
sudo bifroest recording export \
   --with-sensitive \
   --output /root/session.cast \
   default YOUR_RECORDING_UUID
```

**Protect the evidence and export:** without a configured encryption recipient, signatures protect integrity, not confidentiality. The exported Cast can contain printed secrets and is never redacted. Bifröst does **not** capture raw keyboard input or SFTP/forwarding payloads; `portForwardingAllowed: false` prevents forwarding in this example. A local recording failure stops the affected task by default. Decide on storage, retention and optional encryption before production use; see the [audit](../reference/auditlog/index.md) and [recording](../reference/auditlog/recording.md) references.
