---
description: Export the SSH certificate authority of a Bifröst flow.
---

# `bifroest key export ca`

Loads the same configuration as `bifroest run` and exports the effective SSH certificate authority of the selected flow. If the private CA does not exist, it is generated before its public key is exported. No `.pub` companion file is created.

## Syntax

`bifroest key export ca [flags] <flowName>`

## Arguments

`flowName` is the name of an SSH-environment flow with certificate authentication enabled.

## Flags {: #key-export-ca-flags }

Includes [all general flags](../../index.md#general-flags).

<<flag("configuration", "File Path", "../../../data-type.md#file-path", aliases=["c"], id_prefix="key-export-ca-", heading=3)>>
Configuration to load. The default is `/etc/engity/bifroest/configuration.yaml` on Unix and `C:\ProgramData\Engity\Bifroest\configuration.yaml` on Windows.

<<flag("output", ref("File Path", "../../../data-type.md#file-path"), default="-", id_prefix="key-export-ca-", heading=3)>>
Output file. `-` writes exactly one LF-terminated OpenSSH public-key line to stdout.

<<flag("force", "bool", default=False, id_prefix="key-export-ca-", heading=3)>>
Replaces an existing output file.

## Examples

See the certificate-authentication examples for [SSH environments](../../../environment/ssh.md#openssh-certificate-authentication) and [Bifröst delegation](../../../authorization/bifroest.md).
