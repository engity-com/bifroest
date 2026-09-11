---
description: How to operate with Bifröst via its Command Line Interface (CLI). What commands are available?
---

# Command line interface (CLI)

Bifröst is usually available via its `bifroest` command on each operating system.

## Running the server {. #run}

Syntax: `bifroest run [flags]`

### Flags {. #run-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", ref("File Path", "data-type.md#file-path", ref("Configuration", "configuration.md")), default="<os specific>", aliases=["c"],id_prefix="run-", heading=4)>>

The default value varies depending on the platform Bifröst runs on:

* Linux: `/etc/engity/bifroest/configuration.yaml`
* Windows: `C:\ProgramData\Engity\Bifroest\configuration.yaml`

## Show version {. #version}

Syntax: `bifroest verion [flags]`

### Flags {. #version-flags}

Includes [all general flags](#general-flags).

## SSH trust bootstrap {: #ssh-trust-bootstrap}

These commands generate and exchange SSH trust material for an [SSH environment](environment/ssh.md) and [Bifröst delegation authorization](authorization/bifroest.md). Only `key import host --address` contacts a remote host.

Exchange exported public material and SHA256 fingerprints over an independently trusted channel.

### Generate a key

Syntax: `bifroest key generate [flags]`

Creates an Ed25519 private key in OpenSSH format. The command never replaces an existing file and never writes private key material to stdout. Private files use mode `0400` on Unix and a protected DACL on Windows. If `--publicFile` is set, the corresponding public key is additionally written as one LF-terminated OpenSSH public-key line.

#### Flags {. #key-generate-flags}

Includes [all general flags](#general-flags).

<<flag("identityFile", "File Path", "data-type.md#file-path", required=True, id_prefix="key-generate-", heading=5)>>
Private key file to create.

<<flag("publicFile", "File Path", "data-type.md#file-path", id_prefix="key-generate-", heading=5)>>
Optional public key file to create. It has to differ from `identityFile` and is never replaced. This explicit output does not enable automatic `.pub` companion files.

### Export a public key

Syntax: `bifroest key export public [flags]`

Writes exactly one LF-terminated OpenSSH public-key line. `--output` defaults to `-` for stdout. A file is written atomically and is not replaced unless `--force` is set.

#### Flags {. #key-export-public-flags}

Includes [all general flags](#general-flags).

<<flag("identityFile", "File Path", "data-type.md#file-path", required=True, id_prefix="key-export-public-", heading=5)>>
Private key file whose public key is exported.

<<flag("comment", "string", id_prefix="key-export-public-", heading=5)>>
Optional OpenSSH public-key comment. Line breaks are not accepted.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="key-export-public-", heading=5)>>
Output file. `-` writes to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-public-", heading=5)>>
Replace an existing output file. Without this flag, an existing file is never modified.

### Export a certificate authority

Syntax: `bifroest key export ca [flags] <flowName>`

Loads the same configuration as `bifroest run` and exports the effective SSH certificate authority of the selected flow. If the private CA does not exist, it is generated before its public key is exported. No `.pub` companion file is created.

#### Argument

`flowName` is the name of an SSH-environment flow with certificate authentication enabled.

#### Flags {. #key-export-ca-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="key-export-ca-", heading=5)>>
Configuration to load. The default is `/etc/engity/bifroest/configuration.yaml` on Unix and `C:\ProgramData\Engity\Bifroest\configuration.yaml` on Windows. Short form: `-c`.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="key-export-ca-", heading=5)>>
Output file. `-` writes exactly one LF-terminated OpenSSH public-key line to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-ca-", heading=5)>>
Replace an existing output file.

### Export host keys

Syntax: `bifroest key export host [flags]`

Creates `known_hosts` entries for an address without network access. With `--identityFile`, that key is loaded or generated. Otherwise all host keys from the selected configuration are loaded or generated.

#### Flags {. #key-export-host-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="key-export-host-", heading=5)>>
Configuration to load when `identityFile` is absent. It uses the same platform default as `bifroest run`. Short form: `-c`.

<<flag("identityFile", "File Path", "data-type.md#file-path", id_prefix="key-export-host-", heading=5)>>
Specific host private-key file to load or create. This cannot be combined with `configuration`.

<<flag("address", "string", required=True, id_prefix="key-export-host-", heading=5)>>
Host represented by the generated entries. Port `22` can be omitted; non-default IPv6 ports use `[address]:port`.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="key-export-host-", heading=5)>>
Output file. `-` writes to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-host-", heading=5)>>
Replace an existing output file.

### Import certificate authorities

Syntax: `bifroest key import ca [flags]`

Validates and atomically merges plain OpenSSH certificate-authority public keys. Certificates, private keys and authorized-key options are rejected.

#### Flags {. #key-import-ca-flags}

Includes [all general flags](#general-flags).

<<flag("trustedCAsFile", "File Path", "data-type.md#file-path", required=True, id_prefix="key-import-ca-", heading=5)>>
Public-key file containing the trusted SSH certificate authorities to update.

<<flag("input", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="key-import-ca-", heading=5)>>
File containing the public CA keys. `-` reads from stdin.

<<flag("expectedFingerprint", "string", id_prefix="key-import-ca-", heading=5)>>
Expected OpenSSH SHA256 fingerprint of every imported CA, or `unknown`. A mismatch leaves the destination unchanged; omission implies `unknown`.

### Import host keys

Syntax: `bifroest key import host [flags]`

Validates and atomically merges normal `known_hosts` entries from a file, stdin or an SSH server. Incoming `@revoked`, `@cert-authority` and certificate entries are rejected.

#### Flags {. #key-import-host-flags}

Includes [all general flags](#general-flags).

<<flag("knownHostsFile", "File Path", "data-type.md#file-path", required=True, id_prefix="key-import-host-", heading=5)>>
OpenSSH `known_hosts` file to update.

<<flag("input", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="key-import-host-", heading=5)>>
File containing entries to import. `-` or omission reads from stdin. This cannot be combined with `address`.

<<flag("address", "string", id_prefix="key-import-host-", heading=5)>>
SSH server from which one negotiated host key is retrieved. Port `22` can be omitted.

<<flag("expectedFingerprint", "string", id_prefix="key-import-host-", heading=5)>>
Expected OpenSSH SHA256 fingerprint, or `unknown`. It is required with `address`; omission for file or stdin input implies `unknown`.

!!! warning
     `--expectedFingerprint unknown` with `--address` explicitly trusts a key obtained from an unverified network peer and can expose the connection to an on-path attack. The command also emits a warning to stderr.

Both import commands lock concurrent merge operations and preserve existing valid entries. A supplied SHA256 fingerprint has to match every imported key, including keys that are already present; any mismatch leaves the destination unchanged.

## Audit journals {: #audit-journals}

Audit commands are strictly read-only with respect to identities and journals. They load the selected configured identity without creating a missing key and use its producer ID as the trust anchor. Stop the Bifröst service before running these commands so the journal remains stable throughout verification.

Run them on quiescent storage whose journal and output parent directories are not writable by untrusted users. The verifier detects observed changes during a scan, but path-based filesystem APIs cannot provide one atomic snapshot across multiple journals or prevent a privileged actor from replacing paths concurrently.

### Verify an audit journal

Syntax: `bifroest audit verify [flags] <auditlogName>`

Verifies the journal head, embedded Ed25519 keys, record signatures, record and segment hash chains, segment seals, file-name hashes, and the configured producer identity. Success produces no output and exits with status `0`.

For an auditlog configured with `encryptionPublicKey` or `encryptionPublicKeyFile`, supply the matching private SSH key. Verification decrypts and authenticates every event payload in memory in addition to checking the journal structure.

#### Flags {. #audit-verify-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="audit-verify-", heading=5)>>
Configuration to load. It uses the same platform default as `bifroest run`. Short form: `-c`.

<<flag("decryptionIdentityFile", "File Path", "data-type.md#file-path", id_prefix="audit-verify-", heading=5)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when verifying journals encrypted for different keys. The key is loaded read-only and is required when an encryption recipient is configured.

### Decrypt an audit journal

Syntax: `bifroest audit decrypt [flags] <auditlogName>`

Decrypts and fully verifies the selected configured journal before writing plaintext JSON Lines. For an unencrypted journal this is equivalent to `audit export`. The command never modifies the source journal and never emits partial output after a verification or decryption failure.

#### Flags {. #audit-decrypt-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="audit-decrypt-", heading=5)>>
Configuration to load. It uses the same platform default as `bifroest run`. Short form: `-c`.

<<flag("decryptionIdentityFile", "File Path", "data-type.md#file-path", id_prefix="audit-decrypt-", heading=5)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when needed. A matching key is required for an encrypted auditlog.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="audit-decrypt-", heading=5)>>
Output file. `-` writes plaintext JSON Lines to stdout. Output paths inside the journal or equal to a signing identity, decryption identity, or referenced encryption public-key file are rejected.

<<flag("force", "bool", default=False, id_prefix="audit-decrypt-", heading=5)>>
Replace an existing output file.

### Export an audit journal

Syntax: `bifroest audit export [flags] <auditlogName>`

Verifies the selected journal completely before writing its records as JSON Lines in their cryptographic chain order. Export uses bounded in-memory materialization and refuses histories exceeding its safety limit; `audit verify` remains available for larger journals without materializing records.

Encrypted auditlogs require the matching `--decryptionIdentityFile`; exported event payloads are always plaintext.

#### Flags {. #audit-export-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="audit-export-", heading=5)>>
Configuration to load. It uses the same platform default as `bifroest run`. Short form: `-c`.

<<flag("decryptionIdentityFile", "File Path", "data-type.md#file-path", id_prefix="audit-export-", heading=5)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag when needed.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="audit-export-", heading=5)>>
Output file. `-` writes JSON Lines to stdout. Output paths inside the journal or equal to its signing identity, a supplied decryption identity, or its referenced encryption public-key file are rejected.

<<flag("force", "bool", default=False, id_prefix="audit-export-", heading=5)>>
Replace an existing output file.

### Merge audit journals

Syntax: `bifroest audit merge [flags] <auditlogName>...`

Verifies every selected journal before producing one deterministic JSON Lines stream. Records are ordered by their producer-signed timestamp and stable origin and chain-position tie-breakers. Timestamps are statements by their producers and are not an independently trusted clock. Like export, merge refuses inputs exceeding its bounded materialization safety limit.

Plaintext and encrypted journals can be merged together. Supply every required private key by repeating `--decryptionIdentityFile`.

#### Flags {. #audit-merge-flags}

Includes [all general flags](#general-flags).

<<flag("configuration", "File Path", "data-type.md#file-path", id_prefix="audit-merge-", heading=5)>>
Configuration to load. It uses the same platform default as `bifroest run`. Short form: `-c`.

<<flag("decryptionIdentityFile", "File Path", "data-type.md#file-path", id_prefix="audit-merge-", heading=5)>>
Private SSH key used to decrypt encrypted event payloads. Repeat the flag for journals encrypted for different keys.

<<flag("output", ref("File Path", "data-type.md#file-path"), default="-", id_prefix="audit-merge-", heading=5)>>
Output file. `-` writes JSON Lines to stdout. Output paths inside any selected journal or equal to a signing identity, supplied decryption identity, or referenced encryption public-key file are rejected.

<<flag("force", "bool", default=False, id_prefix="audit-merge-", heading=5)>>
Replace an existing output file.

Exports and merged streams are derived, unsigned representations. Preserve the original journal files as cryptographic evidence.

## Service management {. #service}

!!! note
     Only available on Windows.

### Installation {. #service-install}

Installation of Bifröst as service inside the operating system, which will let it run upon system start and with full privileges.

Syntax: `bifroest service install [flags]`

#### Flags {. #service-install-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-install-", heading=5)>>
Name of the service.

<<flag("configuration", ref("File Path", "data-type.md#file-path", ref("Configuration", "configuration.md")), default="C:\\ProgramData\\Engity\\Bifroest\\configuration.yaml", aliases=["c"], id_prefix="service-install-", heading=5)>>
Configuration location to use for the installed service.

<<flag("start", "bool", default=True, id_prefix="service-install-", heading=5)>>
If installed, should it be started immediately. This calls implicitly [`bifroest service start`](#service-start).

### Removal {. #service-remove}

Will remove an installed service instance of Bifröst from the operating system.

Syntax: `bifroest service remove [flags]`

#### Flags {. #service-remove-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-remove-", heading=5)>>
Name of the service.

<<flag("stop", "bool", default=True, id_prefix="service-remove-", heading=5)>>
Same as calling [`bifroest service stop`](#service-stop) before this command.

### Start {. #service-start}

Will start the installed service instance of Bifröst.

Syntax: `bifroest service start [flags]`

#### Flags {. #service-start-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-start-", heading=5)>>
Name of the service.

### Stop {. #service-stop}

Will stop the installed service instance of Bifröst (if running).

Syntax: `bifroest service stop [flags]`

#### Flags {. #service-stop-flags}

Includes [all general flags](#general-flags).

<<flag("name", "string", default="engity-bifroest", id_prefix="service-stop-", heading=5)>>
Name of the service.

## General

### Flags {. #general-flags}

<<flag("log.level", "Log Level", "data-type.md#log-level", default="INFO", heading=4)>>
Defines the minimum level at which the log messages will be logged.

<<flag("log.format", "Log Format", "data-type.md#log-format", default="text", heading=4)>>
In which format the log output should be printed.

<<flag("log.colorMode", "Log Color Mode", "data-type.md#log-color-mode", default="auto", heading=4)>>
Tells whether to log in color or not.

<<flag("version", default="auto", heading=4)>>
Same as using sub-command [`version`](#version).
