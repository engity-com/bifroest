suite {
  name = "deliberately-red-unix",
  platform = { os = { "unix" } },
  configuration = file_content("configuration.yaml"),
  environment = object {
    accounts = list { object { name = "alice", uid = 1001 } },
  },
  tests = {
    {
      name = "wrong-target-contract",
      input = object {
        request = object { requestingName = "ops" },
        authentication = object {
          primary = object { outcome = "allow", account = "alice" },
        },
      },
      verify = function(t, actual)
        -- Deliberately ignore the return value. The process must still exit 1.
        t:IsEqual("not-alice", actual.environment.user, "Deliberately red smoke test")
      end,
    },
  },
}
