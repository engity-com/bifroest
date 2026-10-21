---
description: Configure session recording, generate actual SSH output, find the sealed Recording and verify, export or replay it.
---

# Record, find and replay a session

This Linux example adds audit logging and session recording to a local-account host. It generates real SSH command output, finds the sealed Recording through the CLI and replays it. Start with an installed [Bifröst host](../setup/on-host.md) and an allowed local account.

## Examples

### Configure a recorded local-account flow

1. Add the auditlog and flow to the host configuration. This complete example uses the named `default` audit log:

    ```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
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

    The flow selects `default` automatically. Audit journals and Recordings are enabled independently; the default strict failure policy stops an affected task if local persistence fails. See [audit configuration](../reference/auditlog/index.md) and [Recording configuration](../reference/auditlog/recording.md).

2. Restart Bifröst using the host's service manager. For a fresh installation, the default signing key, audit journal and Recording repository are created when enabled.

3. Run a command through the workload SSH connection and let it finish:

    ```shell title="Workload terminal"
    ssh alice@bifroest.example.org 'printf "recording-check\n"'
    ```

    Replace the account and host with your own. Bifröst records shell/command output; it does not capture raw keystrokes or SFTP and forwarding payloads. Forwarding is disabled in this example.

### Find and verify the generated Recording

1. On the Bifröst host, run inspection commands as the service user, with access to its configuration, signing key and repositories:

    ```shell title="Bifröst host"
    bifroest recording ls default --limit=20
    ```

    The default Linux repository is `/var/lib/engity/bifroest/recordings`; the CLI verifies selected sealed originals in its `sealed/` directory. If there are several entries, use their start times to find the test session; listing order is by Recording ID.

2. Replace `RECORDING_UUID` with its ID and inspect and verify it:

    ```shell title="Bifröst host"
    bifroest recording show default RECORDING_UUID --format=json
    bifroest recording verify default RECORDING_UUID --require-full
    bifroest audit verify default
    ```

    The configured signing identity supplies local producer trust. This clear Recording receives full verification without a decryption key.

### Replay or export its terminal output

1. Replay the Recording in the terminal:

    ```shell title="Bifröst host"
    bifroest recording play default RECORDING_UUID --with-sensitive --speed=2
    ```

    The verified playback includes `recording-check` from the generated command.

2. To save an asciicast v3 file instead, choose an existing private output directory outside managed storage:

    ```shell title="Bifröst host"
    bifroest recording export default RECORDING_UUID \
      --with-sensitive \
      --output /srv/audit-evidence/session.cast
    ```

    Recording exports are complete, sensitive plaintext and are never redacted. Without an encryption recipient, signatures protect integrity but not confidentiality of the stored original either.

## Next steps

* [Manage a host remotely](management.md) adds a separate administration flow and workstation alias.
* [Verify encrypted evidence on a workstation](evidence.md) configures encryption and keeps private decryption keys off the server.
* [`recording` command reference](../reference/cli/recording/index.md) documents all arguments, flags and execution modes.
