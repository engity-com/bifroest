---
description: Bifröst has to do in periodic intervals clean-up tasks, to ensure no sessions and connections are dangling around.
---

# Housekeeping

Bifröst has to do in periodic intervals clean-up tasks, to ensure no sessions and connections are dangling around.

## Properties

<<property("every", "Duration", "data-type.md#duration", default="10m")>>
How often the housekeeping should run.

<<property("initialDelay", "Duration", "data-type.md#duration", default=0)>>
How long should be waited upon start of the application before the first run. If `0` it is also blocking, before even the first connection will be accepted.

<<property("autoRepair", "bool", default=True)>>
If `true` the service will try to repair maybe corrupt/broken states by itself, if safe possible.

<<property("keepExpiredFor", "Duration", "data-type.md#duration", default="336h")>>
For how long a disposed session will be kept. The session will no longer be usable, but it might be helpful for audit reasons.

!!! note
    `336h` = 14 days
