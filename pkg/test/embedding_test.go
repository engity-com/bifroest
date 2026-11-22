package test_test

import (
	"testing"

	bftest "github.com/engity-com/bifroest/pkg/test"
	"github.com/stretchr/testify/require"
)

func TestEmbeddingCanSupplyBinaryVersionWithoutHostCapabilities(t *testing.T) {
	source := []byte(`suite {
 name="embedded",
 platform={version={"1.2"}},
 environment=object{accounts=list{}},
 tests={{name="denied",input=object{request=object{requestingName="ops"},authentication=object{primary=object{outcome="deny"}}},
 verify=function(t,actual) t:IsEqual("deny",actual.decision) end}}
}`)
	configuration := []byte(`flows:
 - name: primary
   requirement:
     includedRequestingName: '^ops$'
   authorization:
     type: local
     principal: 'mapped-{{ .authentication.principal }}'
   environment:
     type: ssh
     address: example.invalid
     user: '{{ .authentication.principal }}'
     acceptAllHostKeys: true
     portForwardingAllowed: false
`)
	report := bftest.RunSourcesWithOptions(t.Context(), source, configuration, bftest.Options{Platform: bftest.Platform{Version: "1.2.7"}})
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Len(t, report.Results, 1)
	require.Empty(t, report.SkippedSuites)
	report = bftest.RunSourcesWithOptions(t.Context(), source, configuration, bftest.Options{Platform: bftest.Platform{Version: "development"}})
	require.Equal(t, 2, report.ExitCode())
	require.Empty(t, report.Results)
	require.Len(t, report.SkippedSuites, 1)
}
