-- Match the runner's positive global allowlist, not an unrestricted Lua runtime.
std = {
  read_globals = {
    "suite", "object", "list", "null", "file_content",
    "assert", "error", "type", "tostring", "tonumber",
    "pairs", "ipairs", "next", "select", "pcall",
  },
}
max_line_length = 100
codes = true

-- Only this editor library declares the runtime-provided globals. Real suites
-- retain the read-only allowlist above; this is not an undefined-global bypass.
files["pkg/test/types/bifroest.lua"] = {
  std = { globals = { "suite", "object", "list", "null", "file_content" } },
}
