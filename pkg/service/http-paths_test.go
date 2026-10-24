package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestHTTPRuntimePathsProtectPrivateStateAndPublicAssetsAtomically(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*configuration.Configuration)
		want      string
	}{
		{"ACME in session storage", func(c *configuration.Configuration) {
			c.Http.Tls.Acme.Storage = filepath.Join(c.Session.V.(*configuration.SessionFs).Storage, "acme")
		}, "HTTPS ACME storage overlaps session storage"},
		{"TLS key in journal", func(c *configuration.Configuration) {
			c.Http.Tls.Certificates[0].PrivateKeyFile = filepath.Join(c.Auditlogs[0].Directory, "tls.pem")
		}, "HTTPS private key file overlaps"},
		{"TLS key equals SSH key", func(c *configuration.Configuration) {
			paths, err := c.Ssh.Keys.HostKeys.Render(noopContext{})
			require.NoError(t, err)
			c.Http.Tls.Certificates[0].PrivateKeyFile = paths[0]
		}, "overlaps SSH host key"},
		{"ACME contains TLS files", func(c *configuration.Configuration) {
			c.Http.Tls.Acme.Storage = filepath.Dir(c.Http.Tls.Certificates[0].PrivateKeyFile)
		}, "HTTPS ACME storage overlaps HTTPS"},
		{"public overlay contains sessions", func(c *configuration.Configuration) {
			c.Http.AssetsDirectory = filepath.Dir(c.Session.V.(*configuration.SessionFs).Storage)
		}, "HTTP asset directory overlaps"},
		{"public overlay in ACME", func(c *configuration.Configuration) {
			c.Http.AssetsDirectory = filepath.Join(c.Http.Tls.Acme.Storage, "public")
		}, "HTTP asset directory overlaps HTTPS ACME storage"},
		{"custom CSS reads TLS key", func(c *configuration.Configuration) {
			c.Http.CustomCss = configuration.HttpAssetFiles{c.Http.Tls.Certificates[0].PrivateKeyFile}
		}, "HTTP customization file overlaps HTTPS private key"},
		{"custom JS reads audit key", func(c *configuration.Configuration) {
			c.Http.CustomJs = configuration.HttpAssetFiles{c.Auditlogs[0].IdentityFile}
		}, "HTTP customization file overlaps auditlog"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := httpListenerTestConfiguration(t)
			httpListenerTestCertificate(t, &conf, nil)
			test.configure(&conf)
			original := conf.Http
			originalKey, originalStorage := original.Tls.Certificates[0].PrivateKeyFile, original.Tls.Acme.Storage
			err := validateRuntimePaths(&conf)
			require.ErrorContains(t, err, test.want)
			require.Same(t, original, conf.Http)
			require.Equal(t, originalKey, conf.Http.Tls.Certificates[0].PrivateKeyFile)
			require.Equal(t, originalStorage, conf.Http.Tls.Acme.Storage)
		})
	}
}

func TestHTTPRuntimePathsRejectHardLinkedCustomizationInputs(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	key := conf.Http.Tls.Certificates[0].PrivateKeyFile
	alias := filepath.Join(filepath.Dir(key), "public.css")
	require.NoError(t, os.Link(key, alias))
	conf.Http.CustomCss = configuration.HttpAssetFiles{alias}
	require.ErrorContains(t, validateRuntimePaths(&conf), "HTTP customization file overlaps HTTPS private key")
}

func TestDisabledHttpDoesNotInspectUnusedHttpPaths(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.Http.Enabled = false
	conf.Http.Tls.Acme.Storage = conf.Session.V.(*configuration.SessionFs).Storage
	conf.Http.AssetsDirectory = conf.Http.Tls.Acme.Storage
	require.NoError(t, validateRuntimePaths(&conf))
}
