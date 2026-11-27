# Development tooling

Use MISE 2026.10.17 or newer and invoke tasks, for example `mise run install:go`,
`mise run install:web` and `mise run test:go:native`. Each executable task declares
its own MISE tools; running it installs missing tools as needed. Go is the only
global MISE prerequisite: Go-backed installers need it before task-local PATH
activation. Its version still comes exclusively from the catalog. All other
tools are task-local; `mise install` installs only Go. System dependencies such as
a container daemon, native compiler/PAM headers and OpenSSH remain host requirements.

`mise run lint:lua` installs its catalog-pinned Luacheck release binary and
Aqua-backed StyLua without APT, LuaRocks or administrator privileges. The upstream
Luacheck binaries support Linux/x64 and Windows/x64; this task fails explicitly
on unsupported hosts rather than selecting another platform's binary. StyLua
checks formatting; Luacheck retains the repository's strict global allowlist.
`mise run format:lua` remains a StyLua-only task.

`mise.tools.yaml` is the version catalog, imported into MISE's `vars`. Every entry
is a quoted `tool_version_<tool>` string. Tasks reference those variables; backend
aliases live in `[tool_alias]` in `mise.toml`. Add a tool there rather than adding
versions or job-specific tool lists to workflows.

Current workflows require these tasks and this catalog in the selected source
revision. Rebuilding older tags without them is not supported.

The existing daily dependency PR also checks this catalog. It generates a
temporary MISE `[tools]` configuration and uses `mise outdated --bump --json`;
MISE selects versions and preserves request precision without installing updates.
`mise run dependencies:tools:check` previews the proposals without editing files or
GitHub (like the other build CLI commands, it requires `GITHUB_TOKEN`).
All dependency checks must succeed before the bot publishes a combined update.

Tool updates are not auto-merged. Go license assets/metadata and the reviewed
browser runtime checks still require explicit review when their toolchains change;
do not bypass failing validation by weakening those checks.
