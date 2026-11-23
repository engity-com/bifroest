suite {
  name = "ssh-target-unix",
  platform = { os = { "unix" } },
  configuration = file_content("configuration.yaml"),
  environment = object {
    accounts = list { object { name = "alice", uid = 1001 } },
  },
  tests = {
    {
      name = "mapped-principal-target",
      input = object {
        request = object { requestingName = "ops" },
        authentication = object {
          primary = object { outcome = "allow", account = "alice" },
        },
      },
      verify = function(t, actual)
        t:IsEqual("selected", actual.decision)
        t:IsEqual("primary", actual.flow)
        t:IsEqual(true, actual.authenticationAssumed)
        t:IsEqual("mapped-alice", actual.identity.principal)
        t:IsEqual("local", actual.identity.issuer)
        t:IsEqual("1001", actual.identity.subject)
        t:IsEqual("work.example.:22", actual.environment.address)
        t:IsEqual("mapped-alice", actual.environment.user)
        t:IsEqual(false, actual.environment.portForwardingAllowed)
        t:IsEqual("ops", t.input.request.requestingName)
        t:IsEqual("alice", t.environment.accounts[1].name)
      end,
    },
  },
}
