# SSH and local-target examples

From the repository root:

```text
bifroest test pkg/test/examples/ssh --excludes '^deliberately-red-'
bifroest test pkg/test/examples/ssh --includes '^deliberately-red-'
```

The first command passes two tests and skips the three opposite-platform tests;
the second intentionally fails one assertion and returns 1. For single-file
runs, choose `green-unix_bftest.lua` / `red-unix_bftest.lua` on Linux/macOS or
`green-windows_bftest.lua` / `red-windows_bftest.lua` on Windows.

`local-unix_bftest.lua` and `local-windows_bftest.lua` demonstrate `mapped-local`,
production `remoteName` resolution, separate authentication/target accounts and
flow-specific group facts. YAML is read relative to the physical suite file.

These tests use synthetic account facts and assumed authentication. No native
login, host-account lookup/provisioning or SSH connection occurs; `selected` is
not complete access authorization.

See the [guide](../../../../docs/guides/testing.md),
[local identity reference](../../../../docs/reference/testing/local.md),
[CLI reference](../../../../docs/reference/cli/test.md) and
[other examples](../../README.md).
