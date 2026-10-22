package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestEnabledHttpCannotSilentlyStartSshOrCreateServiceResources(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "not-created")
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`http:
  enabled: true
  addresses: ['127.0.0.1:0']
  domains: [app.example.org]
  tls:
    certificates: [{certificateFile: missing.pem, privateKeyFile: missing-key.pem}]
flows:
  - name: test
    authorization: {type: oidcDeviceAuth, issuer: 'https://unreachable.invalid', clientId: test, clientSecret: example}
    environment: {type: dummy}
`), ""))
	conf.Ssh.Keys.HostKeys = template.MustNewStrings(filepath.Join(storage, "ssh-key"))
	conf.Session.V.(*configuration.SessionFs).Storage = filepath.Join(storage, "sessions")
	definition := &Service{Configuration: conf, Version: serviceTestVersion{}}
	err := definition.Run(context.Background())
	require.ErrorContains(t, err, "HTTP endpoint is not implemented yet")
	require.ErrorContains(t, err, "http.enabled=true")
	_, err = os.Stat(storage)
	require.True(t, os.IsNotExist(err), "HTTP guard must run before keys, sessions, authorizers or listeners are prepared")
}

func TestHttpDiscoveryCollisionsFailServicePreparationBeforeTransportGuard(t *testing.T) {
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`http:
  domains: [app.example.org]
  tls:
    certificates: [{certificateFile: missing.pem, privateKeyFile: missing-key.pem}]
flows:
  - name: first
    discoverAsSlug: foo
    authorization: {type: none}
    environment: {type: dummy}
  - name: second
    discoverAsSlug: foo
    requirement:
      http: {includedHost: '^other\.example\.org$'}
    authorization: {type: none}
    environment: {type: dummy}
`), ""))
	conf.Http.Enabled = true
	conf.Flows[1].Requirement.Http.IncludedHost = common.MustNewRegexp(`^app\.example\.org$`)
	definition := &Service{Configuration: conf}
	_, err := definition.prepare()
	require.ErrorContains(t, err, "same slug")
	require.NotContains(t, err.Error(), "not implemented")
}
