# Optional Lua editor hints

`bifroest.lua` contains editor-only EmmyLua-style declarations for `suite`,
`object`, `list`, `file_content`, `null`, the `verify` callback and common result
fields. It is not an implementation, runtime dependency or executable include.
The runner discovers only `*_bftest.lua`; never rename this file to that suffix.

For GoLand, install a compatible Lua/EmmyLua plugin and let it index this project
file. If it needs an explicit library location, select `pkg/test/types`. LuaLS
can use the same directory as a workspace library. No `.idea` settings or plugin
installation is imposed on contributors.

The declarations help navigation/completion; they do not validate the entire
data schema or enforce immutable views. Missing facts, platform-specific rules,
runtime limits and assertions are still checked by Bifröst. GoLand's UI behavior
has not been verified by the automated repository checks.

See the [guide](../../../docs/guides/testing.md) and
[reference](../../../docs/reference/testing/index.md). Repository linting uses
`.luacheckrc`; these hints do not grant extra globals to executable test suites.
