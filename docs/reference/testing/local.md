---
description: Properties of a suite's environment facts, including accounts, groups and explicit absences.
---

# Environment facts {: #environment }
<span id="accounts"></span>

Describe users and groups that should exist **for the test**. They do not need
to exist on your computer. An account record, an assumed authentication result
and a selected target user are separate things.

Use an `object` as [`suite.environment`](suites.md#property-environment). Omitted
observations are unknown, not automatically absent. If a rule needs an unknown
account or metadata value, the test errors instead of looking it up on the host.
Contradictory observations and wrong-platform facts are rejected. The binary's
platform determines the account format; a [platform selector](suites.md#platform)
does not emulate another OS.

## Properties

<<property("accounts", array_ref("Account", "#account"), optional=True, heading=3)>>
Known existing accounts. Omission supplies no existing-account observations.
Use `list {}` when none are needed. This does not declare every other name absent.

<<property("absentNames", array_ref("string"), optional=True, heading=3)>>
Names explicitly known not to exist. Absence by name does not invent an absence
observation for an unrelated identifier.

<<property("absentUIDs", array_ref("Unix ID", "data-types.md#unix-id"), optional=True, heading=3)>>
**Unix only.** UIDs explicitly known not to exist.

<<property("absentSIDs", array_ref("SID", "data-types.md#sid"), optional=True, heading=3)>>
**Windows only.** Account SIDs explicitly known not to exist.

<<property("localGroups", array_ref("Windows local group", "#local-group"), optional=True, heading=3)>>
**Windows only.** Known local groups and their direct SID members, for management
group checks. Account group metadata alone is not that membership evidence.
No nested/domain membership expansion is performed.

<<property("absentGroupNames", array_ref("string"), optional=True, heading=3)>>
**Windows only.** Local group names explicitly known not to exist.

## Account {: #account }

Each entry in `environment.accounts` describes one known account. Optional
metadata must be supplied when a tested rule reads it; nothing here requests
account creation.

<<property("name", "string", required=True, id_prefix="account-", heading=3)>>
Account name. Windows requires a valid local SAM account name, not a domain or
Microsoft Entra identity. Unix name comparison is case-sensitive; Windows
account-name matching is case-insensitive.

<<property("uid", "Unix ID", "data-types.md#unix-id", id_prefix="account-", heading=3)>>
**Required on Unix; not accepted on Windows.** The account UID.

<<property("sid", "SID", "data-types.md#sid", id_prefix="account-", heading=3)>>
**Required on Windows; not accepted on Unix.** The account SID.

<<property("displayName", "string", optional=True, id_prefix="account-", heading=3)>>
Display name for rules that read it. There is no guessed name or host lookup.

<<property("homeDir", "string", optional=True, id_prefix="account-", heading=3)>>
Home/profile directory for rules that read it. Supplying a path does not read,
create or load that directory/profile.

<<property("shell", "string", optional=True, id_prefix="account-", heading=3)>>
Shell metadata for rules that read it. No host shell default is consulted.

<<property("group", "Group", "#group", optional=True, id_prefix="account-", heading=3)>>
**Unix only.** Primary group. It is distinct from supplementary `groups`.

<<property("groups", array_ref("Group", "#group"), optional=True, id_prefix="account-", heading=3)>>
Supplementary groups on Unix; direct local alias metadata on Windows. An
omitted list is unknown. An explicit `list {}` is a known empty observation.

## Group {: #group }

An account's primary/supplementary group metadata, used in `accounts[].group`
and `accounts[].groups[]`. Windows has no primary group in this model.

<<property("name", "string", required=True, id_prefix="group-", heading=3)>>
Group name; on Windows, a valid local SAM group name.

<<property("gid", "Unix ID", "data-types.md#unix-id", id_prefix="group-", heading=3)>>
**Required on Unix; not accepted on Windows.** The group GID.

<<property("sid", "SID", "data-types.md#sid", id_prefix="group-", heading=3)>>
**Required on Windows; not accepted on Unix.** The local group SID.

## Windows local group {: #local-group }

Each entry in `environment.localGroups` describes a group and its direct members.

<<property("name", "string", required=True, id_prefix="local-group-", heading=3)>>
Local group name; comparisons are case-insensitive.

<<property("sid", "SID", "data-types.md#sid", required=True, id_prefix="local-group-", heading=3)>>
The group SID, distinct from an account SID in the same fixture.

<<property("members", array_ref("SID", "data-types.md#sid"), optional=True, id_prefix="local-group-", heading=3)>>
The complete direct member SID list. It is required when a membership check
needs it. Omission is unknown; `list {}` means no direct members. Matching uses
SIDs, not display names.

## Examples

Use this object as `suite.environment` on Linux/macOS:

```lua
local environment = object {
  accounts = list { object { name = "alice", uid = 1001 } },
  absentNames = list { "new-account" },
}
```

Use this list as `suite.environment.localGroups` on Windows:

```lua
local localGroups = list {
  object {
    name = "bifroest-managed", sid = "S-1-5-21-1-2-3-3001",
    members = list { "S-1-5-21-1-2-3-1001" },
  },
}
```

## Local account mapping {: #authentication }

For a [local authentication assumption](input.md#authentication), omitted mode
or `post-authentication` means the account name is already resolved. It does
not claim the configured `remoteName` or a native login ran.

`mapped-local` first evaluates the configured [`remoteName`](../authorization/local.md#property-remoteName).
Only `.remote.user` and supported literal/conditional expressions are available
at that step; host, connection and credential fields are not supplied. An
optional `account` must agree with the mapping. The resolved account must be a
supplied existing Account for `allow`; unknown/absent accounts are errors.
A mapped-local `deny` still evaluates the mapping before denying.

## Management membership {: #groups }

In configuration templates, `.authorization.user.managed` refers to the
**authenticated account** and the chosen flow's `managedGroup`, not the target
account. For Unix it compares names: a matching primary group needs no
supplementary list; otherwise the supplementary groups must be known. Windows
uses the direct SID membership observations above. A known absent management
group produces the same negative result as the service.

Without a local environment, this template field is present with no value
(`nil`), not `false`. Applicable but unknown membership is an error.
See the [Local User context](../context/local-user.md#property-managed) for
the production meaning; the test supplies its observations instead of reading them.

## Local target settings {: #target-projection }

Returned target fields are documented under [Local target](result.md#local-target).
The local `loginAllowed` rule is checked before target lookup or rendering;
false produces `decision = "deny", stage = "local-login"`. Missing facts or
template failures remain errors. The SSH environment's `loginAllowed` rule is
not evaluated by this scope.

For Windows local targets, every local environment in the loaded YAML must
explicitly provide `shellCommand` and `execCommandPrefix`; empty lists are
valid. This prevents host-dependent defaults from entering the test.
See the <<asset_link("pkg/test/examples/ssh/README.md", "Unix/Windows examples")>>.
