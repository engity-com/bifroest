package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestMonitoringCollectionActivationMatrix(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, management := range []bool{false, true} {
			t.Run(map[bool]string{false: "no-http", true: "http"}[enabled]+"/"+map[bool]string{false: "no-management", true: "management"}[management], func(t *testing.T) {
				conf := monitoringTestConfiguration(t)
				conf.Monitoring.Enabled = enabled
				if management {
					conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
				}
				if !enabled {
					conf.Monitoring.BearerTokenFile = filepath.Join(t.TempDir(), "missing-token")
					conf.Monitoring.Tls.Enabled = true
					conf.Monitoring.Tls.Certificates = []configuration.HttpCertificate{{CertificateFile: "missing.crt", PrivateKeyFile: "missing.key"}}
				}
				m, err := newServiceMonitoring(conf)
				require.NoError(t, err, "disabled HTTP must not read credentials")
				if !enabled && !management {
					require.Nil(t, m)
					return
				}
				require.NotNil(t, m)
				require.Equal(t, enabled, m.endpoint != nil)
				defer m.endpoint.Close()
				m.setReady(true)
				snapshot, err := m.Snapshot(t.Context(), []string{"bifroest_ready"})
				require.NoError(t, err)
				require.Len(t, snapshot.Families, 1)
				require.Equal(t, 1.0, snapshot.Families[0].Metric[0].GetGauge().GetValue())
				m.setReady(false)
			})
		}
	}
	conf := monitoringTestConfiguration(t)
	conf.Monitoring = nil
	conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	m, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Nil(t, m.endpoint)
}

func TestMonitoringPreparationWithoutCollectorAndStableProcessStart(t *testing.T) {
	conf := monitoringTestConfiguration(t)
	conf.Monitoring.Tls.Enabled = true
	svc := &service{Service: &Service{Configuration: conf}}
	require.NoError(t, svc.prepareHTTPS(), "preparation without a collector must remain nil-safe")
	conf.Monitoring.Tls.Enabled = false
	m, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	first, err := m.Snapshot(t.Context(), nil)
	require.NoError(t, err)
	// Missing process observations must not look like a restart. Simulate an
	// entirely empty gatherer; no running service is using this test registry.
	m.registry = prometheus.NewRegistry()
	second, err := m.Snapshot(t.Context(), []string{"bifroest_ready"})
	require.NoError(t, err)
	require.Empty(t, second.Families)
	require.Equal(t, first.ProcessStartedAt, second.ProcessStartedAt)
}

func TestManagementMetricsSnapshotExactFamiliesAndAbsentValues(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	m.service.Store(&service{})
	for _, name := range []string{"bifroest_sessions_average_age_seconds", "bifroest_http_requests_total", "bifroest_http_request_duration_seconds", "bifroest_auditlog_available_bytes"} {
		snapshot, err := m.Snapshot(t.Context(), []string{name})
		require.NoError(t, err, name)
		require.Empty(t, snapshot.Families, "known but absent families must not be filled with zero")
	}
	for _, name := range []string{"unknown", "bifroest_sessions_active.*", "sum(bifroest_sessions_active)", "bifroest_http_request_duration_seconds_bucket", "bifroest_sessions_active{flow=\"shell\"}"} {
		snapshot, err := m.Snapshot(t.Context(), []string{"bifroest_ready", name})
		require.ErrorContains(t, err, "unknown metric family")
		require.Empty(t, snapshot.Families, "invalid selections must return no partial result")
	}
	m.observeFlow(authorization.FlowAuthorizationObservation{Flow: "shell", Duration: 100 * time.Millisecond})
	snapshot, err := m.Snapshot(t.Context(), []string{"bifroest_authentication_flow_evaluation_duration_seconds", "bifroest_ready", "bifroest_ready"})
	require.NoError(t, err)
	require.Len(t, snapshot.Families, 2)
	histogram := snapshot.Families[0]
	require.Equal(t, dto.MetricType_HISTOGRAM, histogram.GetType())
	require.Len(t, histogram.Metric, 1)
	require.Len(t, histogram.Metric[0].Histogram.Bucket, 9)
	require.Equal(t, uint64(1), histogram.Metric[0].Histogram.GetSampleCount())
	require.Equal(t, 0.1, histogram.Metric[0].Histogram.GetSampleSum())
	require.Len(t, histogram.Metric[0].Label, 9)
	require.False(t, snapshot.CapturedAt.Before(snapshot.ProcessStartedAt))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = m.Snapshot(ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
	all, err := m.Snapshot(t.Context(), nil)
	require.NoError(t, err)
	require.Greater(t, len(all.Families), 10)
	for _, family := range all.Families {
		filtered, err := m.Snapshot(t.Context(), []string{family.GetName()})
		require.NoError(t, err)
		require.Len(t, filtered.Families, 1)
	}
}

func TestManagementMetricsSSHFormatsFiltersAndWire(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Monitoring = &configuration.Monitoring{}
		require.NoError(t, conf.Monitoring.SetDefaults())
		conf.Monitoring.BearerTokenFile = "must-not-be-read"
	})
	require.Nil(t, server.service.monitoring.endpoint)
	client := server.mustDial(t)
	for _, selected := range []string{"", " --format=table", " --format=json", " --format=openmetrics"} {
		command, err := client.NewSession()
		require.NoError(t, err)
		output, err := command.Output("metrics show bifroest_connections_active bifroest_sessions_active" + selected)
		require.NoError(t, err)
		require.Contains(t, string(output), "bifroest_connections_active")
		require.Contains(t, string(output), "bifroest_sessions_active")
		require.NotContains(t, string(output), "bifroest_authentication_attempts")
		switch selected {
		case " --format=json":
			var decoded struct {
				CapturedAt time.Time         `json:"capturedAt"`
				Families   []json.RawMessage `json:"families"`
			}
			require.NoError(t, json.Unmarshal(output, &decoded))
			require.Len(t, decoded.Families, 2)
			require.False(t, decoded.CapturedAt.IsZero())
		case " --format=openmetrics":
			require.True(t, bytes.HasSuffix(output, []byte("# EOF\n")))
		default:
			require.Contains(t, string(output), "METRIC")
			require.Contains(t, string(output), "VALUE")
			require.Contains(t, string(output), "LABELS")
		}
	}
	for _, args := range [][]string{{"metrics", "show"}, {"metrics", "show", "bifroest_ready"}, {"metrics", "show", "bifroest_http_requests_total"}} {
		command, err := client.NewSession()
		require.NoError(t, err)
		request, err := transport.EncodeWireRequest(args)
		require.NoError(t, err)
		command.Stdin = bytes.NewReader(request)
		output, err := command.Output(transport.WireCommand)
		require.NoError(t, err)
		var snapshot model.MetricsSnapshot
		require.NoError(t, transport.DecodeWireResult(bytes.NewReader(output), &snapshot))
		require.False(t, snapshot.CapturedAt.IsZero())
		if len(args) == 2 {
			require.Greater(t, len(snapshot.Families), 10)
		} else if args[2] == "bifroest_ready" {
			require.Len(t, snapshot.Families, 1)
		} else {
			require.Empty(t, snapshot.Families)
		}
	}
	for _, args := range []string{"metrics show unknown", "metrics show --format=yaml", "metrics show --format=cbor", "metrics show --format=openmetric", "metrics show @private-file"} {
		command, err := client.NewSession()
		require.NoError(t, err)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output(args)
		require.Error(t, err, args)
		require.Empty(t, output, args)
		require.NotEmpty(t, stderr.String())
	}
}

func TestManagementMetricsForcedCommandDoesNotBroadenAccess(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, `command="metrics show bifroest_ready --format=json"`, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	client := server.mustDial(t)
	for _, requested := range []string{"metrics show", "metrics show bifroest_connections_active", transport.WireCommand} {
		command, err := client.NewSession()
		require.NoError(t, err)
		request, err := transport.EncodeWireRequest([]string{"metrics", "show"})
		require.NoError(t, err)
		command.Stdin = bytes.NewReader(request)
		output, err := command.Output(requested)
		require.NoError(t, err)
		require.Contains(t, string(output), "bifroest_ready")
		require.NotContains(t, string(output), "bifroest_connections_active")
	}
}

func TestManagementMetricsNotAvailableInWorkloadFlow(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		_, err := io.WriteString(task.SshSession(), "workload-command")
		return 0, err
	}})
	client := server.mustDial(t)
	command, err := client.NewSession()
	require.NoError(t, err)
	output, err := command.Output("metrics show")
	require.NoError(t, err)
	require.Equal(t, "workload-command", string(output))
	require.Nil(t, server.service.monitoring)
}

func TestMonitoringSSHLimitCallbackMappingsAndConcurrency(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, enableMonitoringTest)
	m := server.service.monitoring
	reasons := map[essh.LimitRejectionReason]string{
		essh.LimitRejectionMaxStartups: "startups", essh.LimitRejectionMaxConnections: "connections",
		essh.LimitRejectionMaxChannels: "channels", essh.LimitRejectionMaxChannelsPerConnection: "channels_per_connection",
		essh.LimitRejectionMaxSessionsPerConnection: "sessions_per_connection", essh.LimitRejectionMaxReverseForwards: "reverse_forwards",
		essh.LimitRejectionMaxReverseForwardsPerConnection: "reverse_forwards_per_connection", essh.LimitRejectionReason(255): "unknown",
	}
	var wait sync.WaitGroup
	for _, endpoint := range []struct {
		server    *essh.Server
		transport string
	}{{&server.service.server, "ssh"}, {&server.service.tunnelServer, "ssh_tunnel"}} {
		for reason := range reasons {
			for range 5 {
				wait.Go(func() { require.NoError(t, endpoint.server.LimitRejectedCallback(reason)) })
			}
		}
	}
	wait.Wait()
	for _, label := range reasons {
		for _, transport := range []string{"ssh", "ssh_tunnel"} {
			require.Equal(t, 5.0, testutil.ToFloat64(m.access.rejected.WithLabelValues(transport, label)))
		}
	}
}

func TestManagementMetricsIntegratedSSHAndOutputSafety(t *testing.T) {
	directory := t.TempDir()
	identity := filepath.Join(directory, "login")
	login, err := bfcrypto.EnsureKeyFile(identity, &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
	require.NoError(t, err)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		auth := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		auth.Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(bfcrypto.MarshalPublicKey(login.PublicKey()))
	})
	hosts := filepath.Join(directory, "known_hosts")
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(server.address)}, server.service.server.HostSigners[0].PublicKey())+"\n"), 0600))
	host, port, err := net.SplitHostPort(server.address)
	require.NoError(t, err)
	config := filepath.Join(directory, "ssh_config")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("Host metrics\n HostName %s\n Port %s\n User %s\n IdentityAgent none\n IdentityFile %q\n UserKnownHostsFile %q\n", host, port, server.username, filepath.ToSlash(identity), filepath.ToSlash(hosts))), 0600))
	target := management.Target{Host: "metrics", SSHConfigFile: config}
	app := server.service.managementApplication
	for _, selected := range []string{"table", "json", "openmetrics"} {
		var output, stderr bytes.Buffer
		ctx := common.ContextWithRemoteTarget(t.Context(), target)
		ctx = cli.ContextWithStdio(ctx, nil, &output, &stderr)
		err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileRemote}}, "metrics", "show", "bifroest_connections_active", "bifroest_sessions_active", "--format="+selected)
		require.NoError(t, err, stderr.String())
		require.Contains(t, output.String(), "bifroest_connections_active")
		require.Contains(t, output.String(), "bifroest_sessions_active")
		require.NotContains(t, output.String(), "bifroest_authentication_attempts_total")
	}
	ctx := cli.ContextWithStdio(t.Context(), nil, io.Discard, io.Discard)
	histogram, err := target.Metrics(ctx, []string{"bifroest_authentication_flow_evaluation_duration_seconds"})
	require.NoError(t, err)
	require.Len(t, histogram.Families, 1)
	require.Equal(t, dto.MetricType_HISTOGRAM, histogram.Families[0].GetType())
	require.NotEmpty(t, histogram.Families[0].Metric)
	for _, metric := range histogram.Families[0].Metric {
		require.Len(t, metric.GetHistogram().Bucket, 9)
		require.Positive(t, metric.GetHistogram().GetSampleCount())
		require.Len(t, metric.Label, 9)
	}
	for _, name := range []string{"bifroest_http_requests_total", "unknown"} {
		var output bytes.Buffer
		ctx := common.ContextWithRemoteTarget(t.Context(), target)
		ctx = cli.ContextWithStdio(ctx, nil, &output, io.Discard)
		err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileRemote}}, "metrics", "show", name, "--format=json")
		if name == "unknown" {
			require.ErrorContains(t, err, "remote metrics command failed")
			require.Empty(t, output.Bytes())
		} else {
			require.NoError(t, err)
			require.Contains(t, output.String(), `"families":[]`)
		}
	}
	for _, path := range []string{identity, hosts, config} {
		original, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(path, 0600))
		output, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		require.NoError(t, err)
		ctx := common.ContextWithRemoteTarget(t.Context(), target)
		ctx = cli.ContextWithStdio(ctx, nil, output, io.Discard)
		err = app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileRemote}}, "metrics", "show")
		require.ErrorContains(t, err, "must not replace")
		require.NoError(t, output.Close())
		current, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, original, current)
	}
}

func TestMonitoringSSHRealChannelLimitRejections(t *testing.T) {
	for _, reason := range []string{"sessions_per_connection", "channels_per_connection", "channels"} {
		t.Run(reason, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				enableMonitoringTest(conf)
				conf.Ssh.MaxSessionsPerConnection, conf.Ssh.MaxChannelsPerConnection, conf.Ssh.MaxChannels = 10, 10, 10
				switch reason {
				case "sessions_per_connection":
					conf.Ssh.MaxSessionsPerConnection = 1
				case "channels_per_connection":
					conf.Ssh.MaxChannelsPerConnection = 1
				case "channels":
					conf.Ssh.MaxChannels = 1
				}
			})
			client := server.mustDial(t)
			first, err := client.NewSession()
			require.NoError(t, err)
			defer first.Close()
			second, err := client.NewSession()
			if second != nil {
				_ = second.Close()
			}
			require.Error(t, err)
			require.Equal(t, 1.0, testutil.ToFloat64(server.service.monitoring.access.rejected.WithLabelValues("ssh", reason)))
			require.Equal(t, 1.0, testutil.ToFloat64(server.service.monitoring.access.rejected), "exactly one rejecting limit, no duplicate producer")
		})
	}
}

func TestMonitoringSSHRealStartupRejection(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		enableMonitoringTest(conf)
		conf.Ssh.MaxStartupsStart, conf.Ssh.MaxStartupsFull, conf.Ssh.MaxStartupsRate = 1, 1, 100
	})
	first, err := net.DialTimeout("tcp", server.address, time.Second)
	require.NoError(t, err)
	defer first.Close()
	require.NoError(t, first.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = bufio.NewReader(first).ReadString('\n')
	require.NoError(t, err)
	second, err := net.DialTimeout("tcp", server.address, time.Second)
	require.NoError(t, err)
	defer second.Close()
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = second.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Equal(t, 1.0, testutil.ToFloat64(server.service.monitoring.access.rejected.WithLabelValues("ssh", "startups")))
}

func TestMonitoringSSHRealReverseForwardLimitRejections(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprint(global), func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{portForwardingAllowed: true}, func(conf *configuration.Configuration) {
				enableMonitoringTest(conf)
				conf.Ssh.MaxReverseForwardsPerConnection, conf.Ssh.MaxReverseForwards = 1, 10
				if global {
					conf.Ssh.MaxReverseForwardsPerConnection, conf.Ssh.MaxReverseForwards = 10, 1
				}
			})
			client := server.mustDial(t)
			first, err := client.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer first.Close()
			reason := "reverse_forwards_per_connection"
			if global {
				client = server.mustDial(t)
				reason = "reverse_forwards"
			}
			second, err := client.Listen("tcp", "127.0.0.1:0")
			if second != nil {
				_ = second.Close()
			}
			require.Error(t, err)
			require.Equal(t, 1.0, testutil.ToFloat64(server.service.monitoring.access.rejected.WithLabelValues("ssh", reason)))
			require.Equal(t, 1.0, testutil.ToFloat64(server.service.monitoring.access.rejected))
		})
	}
}

func TestMonitoringSSHTunnelRealLimitRejection(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) {
				enableMonitoringTest(conf)
				conf.Ssh.MaxSessionsPerConnection = 1
			})
			client := f.dial(t, mode)
			first, err := client.NewSession()
			require.NoError(t, err)
			defer first.Close()
			second, err := client.NewSession()
			if second != nil {
				_ = second.Close()
			}
			require.Error(t, err)
			require.Equal(t, 1.0, testutil.ToFloat64(f.svc.monitoring.access.rejected.WithLabelValues("ssh_tunnel", "sessions_per_connection")))
			require.Equal(t, 1.0, testutil.ToFloat64(f.svc.monitoring.access.rejected))
		})
	}
}

func TestMonitoringSSHConnectionBudgetDoesNotDoubleCount(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		enableMonitoringTest(conf)
		conf.Ssh.MaxConnections = 1
	})
	first := server.mustDial(t)
	defer first.Close()
	second, err := server.dial()
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
	m := server.service.monitoring
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.rejected.WithLabelValues("ssh", "connections")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.rejected))
	require.Zero(t, *server.service.server.MaxConnections, "the library must not apply another connection budget")
}
