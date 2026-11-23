suite {
  name = "deliberately-red-windows",
  platform = { os = { "windows" } },
  configuration = file_content("configuration.yaml"),
  environment = object {
    accounts = list { object { name = "alice", sid = "S-1-5-21-1-2-3-1001" } },
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
        t:IsEqual("not-alice", actual.environment.user, "Deliberately red smoke test")
      end,
    },
  },
}
