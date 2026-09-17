---
description: Inspect and export Bifröst session Recording artifacts.
---

# `bifroest recording`

Recording commands verify sealed session Recording artifacts without changing them. `inspect` emits only metadata, while `export` deliberately emits the captured terminal, standard-output, and standard-error content as a signed asciicast v3 stream.

An embedded signing key proves that an artifact is internally consistent, not who produced it. Supply an independently obtained producer ID when producer identity must be trusted.

## Commands

* [`bifroest recording inspect`](inspect.md) verifies one Recording artifact and emits its metadata as JSON.
* [`bifroest recording export`](export.md) verifies, decompresses, and when necessary decrypts one Recording artifact as asciicast v3.
