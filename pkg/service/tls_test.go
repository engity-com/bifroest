package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

func sharedTLSConfiguration(t *testing.T) configuration.Configuration {
	t.Helper()
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	conf.Tls = configuration.TlsDefinitions{"shared": {
		Certificates: conf.Http.Tls.Certificates,
	}}
	conf.Http.Tls = &configuration.Tls{Reference: "shared"}
	conf.Monitoring = &configuration.Monitoring{}
	require.NoError(t, conf.Monitoring.SetDefaults())
	conf.Monitoring.Enabled = true
	conf.Monitoring.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
	conf.Monitoring.Domains = configuration.ServerNames{"app.example.org"}
	conf.Monitoring.Tls = &configuration.Tls{Reference: "shared"}
	return conf
}

func TestSharedTLSProfileHasOneManagerAndAtomicRotationForBothConsumers(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	svc := prepareHTTPListenerTestService(t, conf)
	require.Len(t, svc.tlsManagers, 1)
	require.Len(t, svc.tlsBindings, 2)
	manager := svc.tlsManagers["tls:shared"]
	require.NoError(t, svc.prepareTLSBindings(t.Context()))
	get := func(consumer, name string) []byte {
		t.Helper()
		selected, err := svc.tlsBindings[consumer].Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
		require.NoError(t, err)
		return selected.Certificates[0].Certificate[0]
	}
	before := get("http", "app.example.org")
	require.Equal(t, before, get("monitoring", ""), "single monitoring identity supports kubelet without SNI")
	other := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &other, nil)
	oldPair, newPair := conf.Tls["shared"].Certificates[0], other.Http.Tls.Certificates[0]
	cert, err := os.ReadFile(newPair.CertificateFile)
	require.NoError(t, err)
	key, err := os.ReadFile(newPair.PrivateKeyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(oldPair.CertificateFile, cert, 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(oldPair.PrivateKeyFile, key, true))
	require.NoError(t, manager.ReloadFiles(t.Context()))
	after := get("http", "app.example.org")
	require.NotEqual(t, before, after)
	require.Equal(t, after, get("monitoring", "app.example.org"))
	snapshot, err := svc.monitoring.Snapshot(t.Context(), []string{"bifroest_tls_binding_ready", "bifroest_tls_certificate_expiration_timestamp_seconds", "bifroest_http_tls_certificate_expiration_timestamp_seconds"})
	require.NoError(t, err)
	require.Len(t, snapshot.Families, 3)
}

func TestSharedTLSRegistersOnlyActiveListenerDomainsAndKeepsBindingsSeparate(t *testing.T) {
	for _, source := range []string{"files", "dummy", "acme-with-files"} {
		for _, monitoringEnabled := range []bool{true, false} {
			name := source + "/monitoring-disabled"
			if monitoringEnabled {
				name = source + "/monitoring-enabled"
			}
			t.Run(name, func(t *testing.T) {
				conf := sharedTLSConfiguration(t)
				conf.Monitoring.Domains = configuration.ServerNames{"other.example.org"}
				conf.Monitoring.Enabled = monitoringEnabled
				profile := conf.Tls["shared"]
				storage := filepath.Join(t.TempDir(), "acme")
				switch source {
				case "dummy":
					profile = configuration.Tls{Dummy: true}
				case "acme-with-files":
					profile.Acme = &configuration.TlsAcme{
						AcceptTerms:  true,
						DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: storage,
					}
				}
				conf.Tls["shared"] = profile
				svc := prepareHTTPListenerTestService(t, conf)
				require.Len(t, svc.tlsManagers, 1)
				require.NoError(t, svc.prepareTLSBindings(t.Context()))
				manager := svc.tlsManagers["tls:shared"]
				expected := []string{"app.example.org"}
				if monitoringEnabled {
					expected = append(expected, "other.example.org")
				}
				require.Len(t, manager.Expirations(), len(expected))
				for _, name := range expected {
					require.Contains(t, manager.Expirations(), name)
					_, err := manager.Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
					require.NoError(t, err)
				}
				_, err := svc.tlsBindings["http"].Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "other.example.org"})
				require.Error(t, err, "sharing TLS must not expand the HTTP binding")
				if monitoringEnabled {
					monitoring := svc.tlsBindings["monitoring"].Config()
					for _, name := range []string{"other.example.org", ""} {
						_, err := monitoring.GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
						require.NoError(t, err)
					}
					_, err := monitoring.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "app.example.org"})
					require.Error(t, err, "sharing TLS must not expand the monitoring binding")
				} else {
					require.NotContains(t, svc.tlsBindings, "monitoring")
					_, err := manager.Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "other.example.org"})
					require.Error(t, err, "disabled listener names and certificate SANs must not register names")
				}
				_, err = manager.Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "unconfigured.example.org"})
				require.Error(t, err)
				require.Len(t, manager.Expirations(), len(expected), "SNI must not register additional names")
				require.NoDirExists(t, storage, "complete file coverage must not open ACME state")
			})
		}
	}
}

func TestUnusedTLSProfilesDoNotInspectFilesOrCreateACMEState(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	unused := filepath.Join(t.TempDir(), "unused")
	conf.Tls["unused"] = configuration.Tls{
		Certificates: []configuration.TlsCertificate{{CertificateFile: filepath.Join(unused, "cert"), PrivateKeyFile: filepath.Join(unused, "key")}},
		Acme:         &configuration.TlsAcme{AcceptTerms: true, DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: filepath.Join(unused, "acme")},
	}
	svc := prepareHTTPListenerTestService(t, conf)
	require.Len(t, svc.tlsManagers, 1)
	require.Empty(t, svc.tlsChallengeAddresses)
	require.NoDirExists(t, unused)
}

func TestNamedDummyTLSIsSharedByHTTPAndMonitoring(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	conf.Tls["shared"] = configuration.Tls{Dummy: true, MinVersion: "1.3"}
	svc := prepareHTTPListenerTestService(t, conf)
	require.Len(t, svc.tlsManagers, 1)
	require.Empty(t, svc.tlsChallengeAddresses)
	require.NoError(t, svc.prepareTLSBindings(t.Context()))
	selected := func(consumer, name string) *tls.Config {
		t.Helper()
		config, err := svc.tlsBindings[consumer].Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
		require.NoError(t, err)
		require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
		return config
	}
	http, monitoring := selected("http", "app.example.org"), selected("monitoring", "")
	require.Equal(t, http.Certificates[0].Certificate, monitoring.Certificates[0].Certificate)
	require.NoError(t, http.Certificates[0].Leaf.CheckSignature(http.Certificates[0].Leaf.SignatureAlgorithm,
		http.Certificates[0].Leaf.RawTBSCertificate, http.Certificates[0].Leaf.Signature))
}

func TestMonitoringTLSPathSafetyDoesNotDependOnHTTP(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	conf.Http = nil
	profile := conf.Tls["shared"]
	keys, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
	require.NoError(t, err)
	profile.Certificates[0].PrivateKeyFile = keys[0]
	conf.Tls["shared"] = profile
	require.NoError(t, conf.Validate())
	require.ErrorContains(t, validateRuntimePaths(&conf), "overlaps SSH host key")
}

func TestMonitoringInlineTLSUsesTheSharedSourcesAndDomainBinding(t *testing.T) {
	for _, source := range []string{"files", "dummy", "acme-with-files"} {
		t.Run(source, func(t *testing.T) {
			conf := sharedTLSConfiguration(t)
			definition := conf.Tls["shared"]
			if source == "dummy" {
				definition = configuration.Tls{Dummy: true}
			}
			storage := filepath.Join(t.TempDir(), "acme")
			if source == "acme-with-files" {
				definition.Acme = &configuration.TlsAcme{
					AcceptTerms:  true,
					DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: storage,
				}
				conf.Http.Tls = &configuration.Tls{Dummy: true}
			} else {
				conf.Http = nil
			}
			definition.MinVersion = "1.2"
			conf.Monitoring.Tls = &definition
			svc := prepareHTTPListenerTestService(t, conf)
			require.NoError(t, svc.prepareTLSBindings(t.Context()))
			manager := svc.tlsManagers["monitoring"]
			require.NotNil(t, manager)
			require.Len(t, manager.Expirations(), 1)
			require.Contains(t, manager.Expirations(), "app.example.org")
			binding := svc.tlsBindings["monitoring"]
			require.NotNil(t, binding)
			require.True(t, binding.Ready())
			for _, name := range []string{"app.example.org", ""} {
				selected, err := binding.Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: name})
				require.NoError(t, err)
				require.Equal(t, uint16(tls.VersionTLS12), selected.MinVersion)
			}
			for _, hello := range []*tls.ClientHelloInfo{
				{ServerName: "other.example.org"},
				{ServerName: "app.example.org", SupportedProtos: []string{acme.ALPNProto}},
			} {
				_, err := binding.Config().GetConfigForClient(hello)
				require.Error(t, err, "monitoring must reject unconfigured names and public ACME challenges")
			}
			require.NoDirExists(t, storage, "complete file coverage must not create an ACME account")
		})
	}
}

func TestMonitoringInlineACMEPathValidationDoesNotMutateTheInputOnFailure(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	definition := conf.Tls["shared"]
	definition.Acme = &configuration.TlsAcme{
		AcceptTerms:  true,
		DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: "monitoring-acme",
	}
	conf.Monitoring.Tls = &definition
	conf.Http.CustomCss = configuration.HttpAssetFiles{definition.Certificates[0].PrivateKeyFile}
	require.NoError(t, conf.Validate())
	original := conf.Monitoring
	require.ErrorContains(t, validateRuntimePaths(&conf), "HTTP customization file overlaps TLS private key")
	require.Same(t, original, conf.Monitoring)
	require.Equal(t, "monitoring-acme", definition.Acme.Storage)
	conf.Http.CustomCss = nil
	require.NoError(t, validateRuntimePaths(&conf))
	require.NotSame(t, original, conf.Monitoring)
	require.True(t, filepath.IsAbs(conf.Monitoring.Tls.Acme.Storage))
	require.Equal(t, "monitoring-acme", definition.Acme.Storage)
}

func TestChallengeOnlyServiceServesProofsWithoutHTTPAndDrainsOnCancellation(t *testing.T) {
	for _, mode := range []string{"alpn-only", "shared-alpn-only"} {
		t.Run(mode, func(t *testing.T) {
			conf := sharedTLSConfiguration(t)
			conf.Http.Enabled = configuration.HttpAcmeTlsAlpnOnly
			conf.Monitoring.Enabled = mode == "shared-alpn-only"
			storage := filepath.Join(t.TempDir(), "acme")
			conf.Tls["shared"] = configuration.Tls{
				Acme: &configuration.TlsAcme{AcceptTerms: true, DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: storage}}
			svc := prepareHTTPListenerTestService(t, conf)
			require.Nil(t, svc.https)
			require.Nil(t, svc.web)
			require.Nil(t, svc.sshTunnel)
			require.NotContains(t, svc.tlsBindings, "http")
			require.Len(t, svc.tlsManagers, 1)
			require.NoError(t, svc.closeTLS())
			account, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			proof, err := (&acme.Client{Key: account}).TLSALPN01ChallengeCert("test-token", "app.example.org")
			require.NoError(t, err)
			source := httpListenerTestSource{started: make(chan struct{}), proof: &proof}
			manager, err := transporttls.NewManaged(transporttls.Config{Profile: conf.Tls["shared"],
				Names: conf.Monitoring.Domains, StartupTimeout: time.Minute}, source)
			require.NoError(t, err)
			svc.tlsManagers["tls:shared"] = manager
			svc.tlsChallenges = transporttls.Registry{}
			require.NoError(t, svc.tlsChallenges.Register(manager))
			ctx, cancel := context.WithCancel(t.Context())
			bound := make(chan net.Listener, 2)
			done := make(chan error, 1)
			go func() {
				_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
					listener, err := address.Listen()
					if err == nil {
						bound <- listener
					}
					return listener, err
				})
				done <- err
			}()
			await := awaitHTTPListenerTestRun(t, done)
			t.Cleanup(func() { cancel(); _ = await() })
			ssh, challenge := <-bound, <-bound
			select {
			case <-source.started:
			case <-time.After(5 * time.Second):
				t.Fatal("challenge-only source was not prepared")
			}
			// A proof is intentionally self-signed; only this test probe bypasses trust.
			probe := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "app.example.org",
				NextProtos: []string{acme.ALPNProto}, InsecureSkipVerify: true}} //nolint:gosec // Local ACME proof.
			connection, err := probe.DialContext(t.Context(), "tcp", challenge.Addr().String())
			require.NoError(t, err)
			require.Equal(t, acme.ALPNProto, connection.(*tls.Conn).ConnectionState().NegotiatedProtocol)
			require.NoError(t, connection.Close())
			probe.Config.NextProtos = []string{"h2"}
			_, err = probe.DialContext(t.Context(), "tcp", challenge.Addr().String())
			require.Error(t, err, "dedicated challenge socket cannot serve application TLS")
			if svc.monitoring != nil && svc.monitoring.endpoint != nil {
				require.False(t, svc.monitoring.endpoint.Ready())
			}
			cancel()
			require.NoError(t, await())
			for _, listener := range []net.Listener{ssh, challenge} {
				rebound, err := net.Listen("tcp", listener.Addr().String())
				require.NoError(t, err)
				require.NoError(t, rebound.Close())
			}
			require.NoDirExists(t, storage)
		})
	}
}

func TestACMEValidationUsesOnlyHTTPAddresses(t *testing.T) {
	for _, mode := range []string{"https", "alpn-only", "custom-https", "custom-alpn-only", "no-active-acme"} {
		t.Run(mode, func(t *testing.T) {
			conf := sharedTLSConfiguration(t)
			definition := conf.Tls["shared"]
			definition.Acme = &configuration.TlsAcme{
				AcceptTerms: true, DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl,
				Storage: filepath.Join(t.TempDir(), "acme"),
			}
			conf.Tls["shared"] = definition
			conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress(":443")}
			switch mode {
			case "alpn-only":
				conf.Http.Enabled = configuration.HttpAcmeTlsAlpnOnly
			case "custom-https", "custom-alpn-only":
				conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:8443"), bnet.MustNewAddress("[::1]:9443")}
				if mode == "custom-alpn-only" {
					conf.Http.Enabled = configuration.HttpAcmeTlsAlpnOnly
				}
			case "no-active-acme":
				conf.Http.Enabled, conf.Monitoring.Enabled = configuration.HttpDisabled, false
			}
			svc := prepareHTTPListenerTestService(t, conf)
			if mode == "no-active-acme" {
				require.Empty(t, svc.tlsChallengeAddresses)
				require.Empty(t, svc.tlsManagers)
			} else {
				require.Len(t, svc.tlsChallengeAddresses, len(conf.Http.Addresses))
				for index, address := range conf.Http.Addresses {
					require.Equal(t, address.String(), svc.tlsChallengeAddresses[index].String())
				}
			}
			require.NoDirExists(t, definition.Acme.Storage, "preparing definitions must not create an ACME account")
		})
	}
}

func TestAlpnOnlyNeverServesApplicationTLSEvenAfterCertificatesAreReady(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.Http.Enabled = configuration.HttpAcmeTlsAlpnOnly
	root := httpListenerTestCertificate(t, &conf, nil)
	svc := prepareHTTPListenerTestService(t, conf)
	require.Nil(t, svc.https)
	require.Nil(t, svc.web)
	require.Nil(t, svc.sshTunnel)
	require.NotContains(t, svc.tlsBindings, "http")
	require.True(t, conf.Http.WebUi.IsEnabled())
	require.True(t, conf.Http.LoginFlow.IsEnabled())
	require.True(t, conf.Http.SshTunnel.IsEnabled())
	ctx, cancel := context.WithCancel(t.Context())
	bound := make(chan net.Listener, 2)
	done := make(chan error, 1)
	go func() {
		_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
			listener, err := address.Listen()
			if err == nil {
				bound <- listener
			}
			return listener, err
		})
		done <- err
	}()
	await := awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); _ = await() })
	<-bound // SSH.
	challenge := <-bound
	require.Eventually(t, svc.tlsManagers["http"].Ready, 5*time.Second, time.Millisecond)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, protocols := range [][]string{nil, {"h2"}, {"http/1.1"}, {acme.ALPNProto, "h2"}} {
		probeContext, stop := context.WithTimeout(t.Context(), 2*time.Second)
		connection, err := (&tls.Dialer{Config: &tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: "app.example.org", RootCAs: roots, NextProtos: protocols,
		}}).DialContext(probeContext, "tcp", challenge.Addr().String())
		if connection != nil {
			_ = connection.Close()
		}
		stop()
		require.Error(t, err, "ALPN-only must reject application TLS even with valid ready certificates")
	}
	require.NoDirExists(t, conf.Http.Tls.Acme.Storage, "complete file coverage must not create an ACME account")
	cancel()
	require.NoError(t, await())
}
