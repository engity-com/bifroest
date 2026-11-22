-- These are explicit assumed verification results, never signed credentials.
local function assumed_identity()
  return object {
    issuer = "https://issuer.example.org",
    subject = "id-123",
    token = null, -- Known absent; no token is needed by this policy.
    idToken = object {
      issuer = "https://issuer.example.org",
      subject = "id-123",
      audience = list { "example-client" },
      expiry = "2030-01-01T00:00:00Z",
      issuedAt = "2020-01-01T00:00:00Z",
      nonce = "",
      accessTokenHash = "",
      claims = object { preferred_username = "alice", groups = list { "operators" } },
    },
    -- UserInfo is unmodeled, not copied from the ID token. The configuration
    -- disables publication of it; it is not a required dependency here.
  }
end

local tests = {}
for _, flow in ipairs { "device", "code" } do
  tests[#tests + 1] = {
    name = flow .. "-mapped-identity",
    input = object {
      request = object { requestingName = flow, method = "keyboard-interactive" },
      authentication = object {
        [flow] = object { outcome = "allow", mode = "verified-oidc", oidc = assumed_identity() },
      },
    },
    verify = function(t, actual)
      t:IsEqual("selected", actual.decision)
      t:IsEqual(t.input.request.requestingName, actual.flow)
      t:IsEqual(true, actual.authenticationAssumed)
      t:IsEqual("verified-oidc", actual.authentication.mode)
      t:IsEqual("id-123", actual.identity.subject)
      t:IsEqual("https://issuer.example.org", actual.identity.issuer)
      t:IsEqual("mapped-alice", actual.identity.principal)
      t:IsEqual("mapped-alice", actual.environment.user)
      t:IsEqual(false, actual.environment.portForwardingAllowed)
    end,
  }
end

suite {
  name = "assumed-oidc",
  configuration = file_content("configuration.yaml"),
  environment = object { accounts = list {} },
  tests = tests,
}
