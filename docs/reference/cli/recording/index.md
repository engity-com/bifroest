---
description: Inspect Bifröst session Recording artifacts.
---

# `bifroest recording`

Recording commands inspect sealed session Recording artifacts without changing them. They do not decrypt encrypted Recordings or emit captured terminal, standard-output, or standard-error content.

An embedded signing key proves that an artifact is internally consistent, not who produced it. Supply an independently obtained producer ID when producer identity must be trusted.

## Commands

* [`bifroest recording inspect`](inspect.md) verifies one Recording artifact and emits its metadata as JSON.
