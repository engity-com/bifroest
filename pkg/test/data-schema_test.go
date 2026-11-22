package test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/errors"
)

func TestFixtureSchemaPropertyNamesRequireExactSpelling(t *testing.T) {
	for _, target := range []any{&input{}, &requestInput{}, &assumption{}, &facts{}, &account{}, &accountGroup{}, &localGroup{}, &authorization.AssumedOidcFacts{}} {
		schema := reflect.TypeOf(target).Elem()
		for index := range schema.NumField() {
			name, _, _ := strings.Cut(schema.Field(index).Tag.Get("json"), ",")
			require.NotEmpty(t, name)
			for _, alias := range []string{strings.ToUpper(name), strings.ToLower(name), strings.ToUpper(name[:1]) + name[1:]} {
				if alias == name {
					continue
				}
				t.Run(schema.Name()+"/"+alias, func(t *testing.T) {
					// Null isolates property spelling from the field's value type;
					// required facts and null eligibility are checked separately.
					value := reflect.New(schema).Interface()
					require.NoError(t, decodeData(map[string]any{name: nil}, value))
					err := decodeData(map[string]any{alias: nil}, value)
					require.Error(t, err)
					require.True(t, errors.Config.IsErr(err))
				})
			}
		}
	}
}

func TestFixtureSchemaRejectsNestedPropertyAliases(t *testing.T) {
	for _, test := range []struct {
		name, canonical, property, alias string
		target                           any
	}{
		{"request", `{"request":{"requestingName":null}}`, "requestingName", "RequestingName", &input{}},
		{"authentication map", `{"authentication":{"UID":{"outcome":null}}}`, "outcome", "Outcome", &input{}},
		{"OIDC identity", `{"authentication":{"Accounts":{"oidc":{"issuer":null}}}}`, "issuer", "Issuer", &input{}},
		{"account list", `{"accounts":[{"name":null}]}`, "name", "Name", &facts{}},
		{"primary group", `{"accounts":[{"group":{"gid":null}}]}`, "gid", "GID", &facts{}},
		{"supplementary groups", `{"accounts":[{"groups":[{"gid":null}]}]}`, "gid", "GID", &facts{}},
		{"local groups", `{"localGroups":[{"members":null}]}`, "members", "Members", &facts{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data any
			require.NoError(t, json.Unmarshal([]byte(test.canonical), &data))
			require.NoError(t, decodeData(data, test.target))
			property := `"` + test.property + `":null`
			alias := `"` + test.alias + `":null`
			for _, replacement := range []string{alias, property + `,` + alias} {
				source := strings.Replace(test.canonical, property, replacement, 1)
				require.NoError(t, json.Unmarshal([]byte(source), &data))
				err := decodeData(data, test.target)
				require.Error(t, err, "%s", source)
				require.True(t, errors.Config.IsErr(err))
			}
		})
	}
}

func TestNumericFactsCannotBypassValidationWithPropertyAliases(t *testing.T) {
	for _, test := range []struct{ name, facts string }{
		{"UID float", `accounts=list{object{name="alice",UID=1001.0}}`},
		{"UID integer alias", `accounts=list{object{name="alice",UID=1001}}`},
		{"Accounts float", `Accounts=list{object{name="alice",uid=1001.0}}`},
		{"primary GID float", `accounts=list{object{name="alice",uid=1001,group=object{name="users",GID=42.0}}}`},
		{"primary Group float", `accounts=list{object{name="alice",uid=1001,Group=object{name="users",gid=42.0}}}`},
		{"supplementary GID float", `accounts=list{object{name="alice",uid=1001,groups=list{object{name="users",GID=42.0}}}}`},
		{"supplementary Groups float", `accounts=list{object{name="alice",uid=1001,Groups=list{object{name="users",gid=42.0}}}}`},
		{"AbsentUIDs float", `AbsentUIDs=list{42.0}`},
		{"lowercase absentuids float", `absentuids=list{42.0}`},
		{"Unicode field alias", `["accountſ"]=list{object{name="alice",uid=1001.0}}`},
		{"duplicate UID aliases", `accounts=list{object{name="alice",uid=1001,UID=1001.0}}`},
		{"duplicate account-list aliases", `accounts=list{},Accounts=list{object{name="alice",uid=1001.0}}`},
		{"duplicate primary-group aliases", `accounts=list{object{name="alice",uid=1001,group=object{name="users",gid=42},Group=object{name="users",gid=42.0}}}`},
		{"duplicate GID aliases", `accounts=list{object{name="alice",uid=1001,groups=list{object{name="users",gid=42,GID=42.0}}}}`},
		{"duplicate absence aliases", `absentUIDs=list{},AbsentUIDs=list{42.0}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `suite{name="schema",environment=object{` + test.facts + `},tests={{name="aliases",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="deny"}}},verify=function(t,actual)t:IsEqual("deny",actual.decision)end}}}`
			report := RunSources(t.Context(), []byte(source), []byte(testConfiguration))
			require.Equal(t, 2, report.ExitCode(), "%+v", report)
			require.Len(t, report.Results, 1)
			require.Equal(t, "config", report.Results[0].Category)
			require.Zero(t, report.Results[0].Assertions)
		})
	}
}

func TestFixtureSchemaPreservesFlowAndArbitraryOidcDataKeys(t *testing.T) {
	source := oidcSource(`
 t:IsEqual("selected",actual.decision)
 t:IsEqual("1001",actual.identity.principal)
 t:IsEqual(1001.0,t.input.authentication.primary.oidc.idToken.claims.UID)
 t:IsEqual("claim-value",t.input.authentication.primary.oidc.idToken.claims.Accounts.UID)
 t:IsEqual("extra-value",t.input.authentication.primary.oidc.token.extra.Accounts.UID)
 `)
	source = strings.Replace(source, `claims=object{preferred_username="alice",`, `claims=object{UID=1001.0,Accounts=object{UID="claim-value"},preferred_username="alice",`, 1)
	source = strings.Replace(source, `extra=object{count=1,`, `extra=object{Accounts=object{UID="extra-value"},count=1,`, 1)
	for _, flow := range []string{"primary", "UID", "Accounts"} {
		t.Run(flow, func(t *testing.T) {
			configuration := strings.Replace(oidcConfiguration("oidcDeviceAuth", `{{ .authorization.idToken.UID }}`, ""), "name: primary", "name: "+flow, 1)
			fixture := strings.ReplaceAll(source, "primary", flow)
			report := RunSources(t.Context(), []byte(fixture), []byte(configuration))
			require.Zero(t, report.ExitCode(), "%+v", report)
			require.Equal(t, Summary{Passed: 1}, report.Summary())
			require.Equal(t, 5, report.Results[0].Assertions)
		})
	}
}
