---
description: Bifröst must carry out some clean-up tasks periodically to ensure no sessions and connections are dangling.
---

# Housekeeping

Bifröst must carry out some clean-up tasks periodically to ensure no sessions and connections are dangling.

## Properties

<<property("every", "Duration", "data-type.md#duration", default="10m")>>
How often the housekeeping should run.

<<property("initialDelay", "Duration", "data-type.md#duration", default=0)>>
How long should be waited upon start of the application before the first run. If `0` it is also blocking, even before the first connection will be accepted.

<<property("autoRepair", "bool", default=True)>>
If `true` the service will try to repair potentially corrupt or broken states by itself, as long as this is safely possible.

<<property("keepExpiredFor", "Duration", "data-type.md#duration", default="336h")>>
For how long a disposed session will be kept. The session will no longer be usable, but it might be helpful for audit reasons.

!!! note
    `336h` = 14 days
