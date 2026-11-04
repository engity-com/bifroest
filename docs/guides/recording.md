---
description: Configure session recording, generate actual SSH output, find the sealed Recording and verify, export or replay it.
---

# Record, find and replay a session

This Linux example adds audit logging and session recording to a local-account host. It generates real SSH command output, finds the sealed Recording through the CLI and replays it. Start with an installed [Bifröst host](../setup/on-host.md) and an allowed local account.

## Examples

### Configure a recorded local-account flow

1. Add the auditlog and flow to the host configuration. This complete example uses the named `default` audit log:

    ```yaml title="Bifröst host: /etc/engity/bifroest/configuration.yaml"
    auditlogs:
      default:
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

    The flow selects the explicitly defined `default` logger automatically; `recording.enabled: true` adds output recording. Without a defined default or explicit logger selection, neither runs. The default strict failure policy stops an affected task if local persistence fails. See [audit configuration](../reference/auditlog/index.md) and [Recording configuration](../reference/auditlog/recording.md).

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

## Browser alternative

The same settings capture output from [browser shells](browser-access.md). With
a management flow and `allowArtifactTransfer: true`:

1. Open **Recordings & audit**. The first page loads newest recordings first;
   choose a source only when several are available. Use **Filter recordings** to
   search by recorded requesting user, flow, time or status.
2. Choose **Open recording**. Set the expected protection and signing identity,
   using an independently retained ID rather than downloaded metadata. Without
   an independent ID, continuing requires an explicit choice and the source
   remains marked as unconfirmed.
3. Choose **Check and open**, then **Play**. Full verification and player
   preparation run locally; playback does not start automatically. Saving an
   export is a separate action.

The player keeps a 16:9 viewing area and scales the recorded terminal
proportionally, without changing its recorded rows or columns. Its bottom
controls provide play/pause, seeking, speed and native fullscreen; fullscreen
uses the whole screen. Seeking reconstructs earlier output and resize events
locally and preserves whether playback was running or paused. Long recordings
may take a moment to reconstruct.

Controls fade after three seconds of inactivity while playing and reappear on
pointer movement or keyboard interaction. They stay visible while paused,
scrubbing or using keyboard-focused controls. With player focus, **Space** or
**K** toggles playback, **Left/Right** seeks five seconds, **J/L** ten seconds,
and **F** toggles fullscreen. **Escape** exits fullscreen. Hardware media keys
are best-effort browser support, without a hidden audio/video source. These
controls neither reconnect to the server nor send terminal input.

Older recordings may lack the requesting user; encrypted identity details are
not exposed by the catalog. Missing values are not inferred from current
accounts. See [encrypted evidence](evidence.md) for trust setup and
[browser limits](../reference/connection/http/security.md) for bounds.

## Next steps

* [Manage a host remotely](management.md) adds a separate administration flow and workstation alias.
* [Verify encrypted evidence on a workstation](evidence.md) configures encryption and keeps private decryption keys off the server.
* [`recording` command reference](../reference/cli/recording/index.md) documents all arguments, flags and execution modes.
