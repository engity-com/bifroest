suite {
  name = "local-target-unix",
  platform = { os = { "unix" } },
  configuration = file_content("local-unix.yaml"),
  environment = object {
    accounts = list {
      object {
        name = "alice",
        uid = 1001,
        homeDir = "/fixture/alice",
        group = object { name = "bifroest-managed", gid = 200 },
      },
      object { name = "mapped-alice", uid = 2001 },
    },
  },
  tests = {
    {
      name = "mapped-local-target",
      input = object {
        request = object { requestingName = "ops" },
        authentication = object {
          primary = object { outcome = "allow", mode = "mapped-local" },
        },
      },
      verify = function(t, actual)
        t:IsEqual("selected", actual.decision)
        t:IsEqual("alice", actual.authentication.remoteName)
        t:IsEqual("alice", actual.authentication.account)
        t:IsEqual("mapped-alice", actual.identity.principal)
        t:IsEqual("local-unix", actual.environment.kind)
        t:IsEqual("mapped-alice", actual.environment.account.name)
        -- A name-based selector does not invent the current target UID.
        t:IsEqual(null, actual.environment.account.uid)
        t:IsEqual("/fixture/alice/work", actual.environment.directory)
        t:IsEqual(true, actual.environment.portForwardingAllowed)
        t:IsEqual(list { "/fixture/sh" }, actual.environment.shellCommand)
      end,
    },
  },
}
