---
no_index: True
description: Bifröst is licensed under Apache License Version 2.0
---

# License

Bifröst's own source code is licensed under the Apache License, Version 2.0,
unless a file's license metadata says otherwise. Third-party code and data keep
their respective licenses; the Apache-2.0 license does not replace those terms.

## Apache License 2.0

!!! note
    This is a copy of the original license file which can be found <<asset_link("LICENSE", "here")>>.

<pre>
--8<-- "LICENSE"
</pre>

## Source tree

The repository follows the [REUSE Specification](https://reuse.software/spec/). [REUSE.toml](https://github.com/engity-com/bifroest/blob/main/REUSE.toml), file headers and the license texts in [LICENSES/](https://github.com/engity-com/bifroest/blob/main/LICENSES/) provide machine-readable copyright and license information for every tracked file. Pull requests and releases run `reuse lint`, and a failed check blocks the corresponding operation.

## Go dependencies

Every release build scans the Go modules actually linked into each Bifröst
binary. The machine-readable policy in
[third-party-license-policy.json](https://github.com/engity-com/bifroest/blob/main/cmd/build/third-party-license-policy.json) distinguishes:

* license identifiers that are approved for automatic use;
* license identifiers explicitly rejected by a reviewed policy decision; and
* license identifiers that require manual review.

The policy currently approves Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC and
MIT. It does not globally reject a license identifier. Every unclassified
license requires manual review and fails the build until a reviewed decision is
recorded. This avoids treating an unknown license as implicitly approved or
rejected.

## Release artifacts

Release archives and container images include the project license, applicable
license texts and an artifact-specific `THIRD_PARTY_NOTICES.txt`. Companion SPDX
2.3 and CycloneDX 1.6 SBOMs identify the components found in each archive or
image. The release manifest relates these files to their platform, edition and
digest; see the [compliance artifacts](../setup/distribution.md#compliance) for
the current release.

The Go dependency policy applies to modules linked into the Bifröst executable.
Container image SBOMs additionally inventory packages inherited from the pinned
base image. Their reported license metadata is preserved without inferring a
Bifröst policy approval; `NOASSERTION` remains where upstream package metadata
does not provide a conclusion.

The documentation build toolchain is not embedded in or distributed with
Bifröst artifacts and is therefore outside this artifact license policy.
