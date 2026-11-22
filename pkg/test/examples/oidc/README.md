# Assumed OIDC examples

From the repository root:

```text
bifroest test pkg/test/examples/oidc --verbose
```

Two platform-independent tests select the SSH flow path with an explicitly
assumed interactive result for each OIDC grant, map the principal and project
an SSH target. They do not verify credentials or signatures, contact the issuer,
start a listener, create sessions or connect to the target.

`configuration.yaml` retains normal production validation, including HTTPS/domain
settings for Code Grant. ID-token metadata is a complete UTC snapshot; claims
use production JSON types. OAuth absence is explicit (`null`); UserInfo is
unmodeled and hidden by `retrieveUserInfo: false`.

See the [OIDC fixture reference](../../../../docs/reference/testing/oidc.md),
[requests](../../../../docs/reference/testing/requests.md),
[CLI reference](../../../../docs/reference/cli/test.md) and
[other examples](../../README.md).
