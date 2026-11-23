-- The endpoint's TLS/domain/origin-header boundary is assumed, not exercised.
-- These are logical HTTP requests and assumed verified identities, not logins.
local function success(flow)
  return object {
    [flow] = object {
      outcome = "allow",
      mode = "verified-oidc",
      oidc = object { issuer = "https://issuer.example.org", subject = "id-123", token = null },
    },
  }
end

local cases = {
  { name = "named-code", slug = "Work", user = "ops", method = "oidc", flow = "work" },
  { name = "nameless-code", slug = "Sso", user = "", method = "oidc", flow = "sso" },
  {
    name = "published-wrong-method-is-pinned",
    slug = "Work",
    user = "ops",
    method = "keyboard-interactive",
  },
  {
    name = "published-wrong-port-is-pinned",
    slug = "Work",
    user = "ops",
    method = "oidc",
    host = "app.example.org:443",
  },
  { name = "published-wrong-name-mode-is-pinned", slug = "Sso", user = "ops", method = "oidc" },
  {
    name = "root-device",
    slug = "",
    user = "ops",
    method = "keyboard-interactive",
    flow = "generic",
  },
  {
    name = "published-denial-is-pinned",
    slug = "Work",
    user = "ops",
    method = "oidc",
    deny = "work",
  },
}
local tests = {}
for _, case in ipairs(cases) do
  local outcomes = object {}
  if case.flow then
    outcomes = success(case.flow)
  end
  if case.deny then
    outcomes = object { [case.deny] = object { outcome = "deny" } }
  end
  local expectedFlow = case.flow
  tests[#tests + 1] = {
    name = case.name,
    input = object {
      request = object {
        transport = "http",
        host = case.host or "APP.Example.Org.:08443",
        slug = case.slug,
        requestingName = case.user,
        method = case.method,
      },
      authentication = outcomes,
    },
    verify = function(t, actual)
      t:IsEqual("http", actual.request.transport)
      t:IsEqual("app.example.org", actual.request.host)
      t:IsEqual(t.input.request.slug, actual.request.slug)
      t:IsEqual(t.input.request.requestingName, actual.request.requestingName)
      local origin = "https://app.example.org:8443"
      if t.input.request.host == "app.example.org:443" then
        origin = "https://app.example.org"
      end
      t:IsEqual(origin, actual.request.origin)
      if not expectedFlow then
        t:IsEqual("deny", actual.decision)
      else
        t:IsEqual("selected", actual.decision)
        t:IsEqual(expectedFlow, actual.flow)
        t:IsEqual("id-123", actual.identity.subject)
        t:IsEqual("mapped-id-123", actual.identity.principal)
        t:IsEqual("mapped-id-123", actual.environment.user)
      end
    end,
  }
end

suite {
  name = "http-selection",
  configuration = file_content("configuration.yaml"),
  environment = object { accounts = list {} },
  tests = tests,
}
