suite {
  name = "local-target-windows",
  platform = { os = { "windows" } },
  configuration = file_content("local-windows.yaml"),
  environment = object {
    accounts = list {
      object { name = "alice", sid = "S-1-5-21-1-2-3-1001", homeDir = "C:/fixture/alice" },
      object { name = "mapped-alice", sid = "S-1-5-21-1-2-3-2001" },
    },
    localGroups = list {
      object {
        name = "bifroest-managed",
        sid = "S-1-5-21-1-2-3-3001",
        members = list { "S-1-5-21-1-2-3-1001" },
      },
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
        t:IsEqual("ALICE", actual.authentication.remoteName)
        t:IsEqual("alice", actual.authentication.account)
        t:IsEqual("mapped-alice", actual.identity.principal)
        t:IsEqual("local-windows", actual.environment.kind)
        t:IsEqual("mapped-alice", actual.environment.name)
        t:IsEqual("", actual.environment.requestedSID)
        t:IsEqual("C:/fixture/alice/work", actual.environment.directory)
        t:IsEqual(true, actual.environment.portForwardingAllowed)
        t:IsEqual(list {}, actual.environment.execCommandPrefix)
      end,
    },
  },
}
