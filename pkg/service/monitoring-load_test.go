package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

// Deliberately bounded, loopback-only lifecycle regressions, not benchmarks or
// capacity claims. Keep the normal protection decisions and check their signals.
func monitoringLoadSnapshot(t *testing.T, m *serviceMonitoring) map[string]float64 {
	t.Helper()
	families, err := m.registry.Gather()
	require.NoError(t, err)
	result := make(map[string]float64)
	for _, family := range families {
		for _, metric := range family.Metric {
			switch {
			case metric.Gauge != nil:
				result[family.GetName()] += metric.Gauge.GetValue()
			case metric.Counter != nil:
				result[family.GetName()] += metric.Counter.GetValue()
			}
		}
	}
	return result
}

func requireMonitoringLoadDrained(t *testing.T, m *serviceMonitoring, physicalHTTP bool) {
	t.Helper()
	names := []string{
		"bifroest_connections_active", "bifroest_connections_unauthenticated",
		"bifroest_sessions_active", "bifroest_session_connections_active", "bifroest_tasks_active",
		"bifroest_http_requests_active", "bifroest_http_channels_active",
		"bifroest_sessions_age_observations", "bifroest_session_connections_age_observations",
	}
	if physicalHTTP {
		names = append(names, "bifroest_http_connections_active", "bifroest_connections_age_observations")
	}
	require.Eventually(t, func() bool {
		values := monitoringLoadSnapshot(t, m)
		for _, name := range names {
			if values[name] != 0 {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond)
	values := monitoringLoadSnapshot(t, m)
	for _, prefix := range []string{"bifroest_sessions", "bifroest_session_connections"} {
		_, exists := values[prefix+"_average_age_seconds"]
		require.False(t, exists, "an empty active set must not expose a fabricated average")
	}
}

func monitoringLoadScraper(t *testing.T, m *serviceMonitoring) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	failures := make(chan error, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				families, err := m.registry.Gather()
				if err == nil {
					for _, family := range families {
						if !strings.HasPrefix(family.GetName(), "bifroest_") {
							continue
						}
						for _, metric := range family.Metric {
							if metric.Gauge != nil && metric.Gauge.GetValue() < 0 {
								err = fmt.Errorf("negative gauge %s", family.GetName())
							}
						}
					}
				}
				if err != nil {
					select {
					case failures <- err:
					default:
					}
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
		select {
		case err := <-failures:
			t.Error(err)
		default:
		}
	}
}

func TestMonitoringBoundedSSHConnectionChurnDrains(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		enableMonitoringTest(conf)
		conf.Ssh.MaxStartupsFull = 0 // Churn, not the separately tested probabilistic startup limiter.
	})
	m := server.service.monitoring
	defer monitoringLoadScraper(t, m)()
	const rounds, unauthenticated = 4, 12
	for range rounds {
		connections := make([]net.Conn, 0, unauthenticated)
		for range unauthenticated {
			conn, err := net.DialTimeout("tcp", server.address, time.Second)
			require.NoError(t, err)
			connections = append(connections, conn)
			t.Cleanup(func() { _ = conn.Close() })
		}
		require.Eventually(t, func() bool {
			return monitoringLoadSnapshot(t, m)["bifroest_connections_unauthenticated"] == unauthenticated
		}, time.Second, 10*time.Millisecond)
		var workers sync.WaitGroup
		failures := make(chan error, 4)
		for range 4 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				client, err := server.dial()
				if err == nil {
					err = client.Close()
				}
				if err != nil {
					failures <- err
				}
			}()
		}
		workers.Wait()
		close(failures)
		for err := range failures {
			require.NoError(t, err)
		}
		for index, conn := range connections {
			if index%2 == 0 {
				if tcp, ok := conn.(*net.TCPConn); ok {
					require.NoError(t, tcp.SetLinger(0))
				}
			}
			require.NoError(t, conn.Close())
		}
		requireMonitoringLoadDrained(t, m, true)
	}
	values := monitoringLoadSnapshot(t, m)
	require.Equal(t, float64(rounds*unauthenticated), values["bifroest_connections_closed_without_authentication_attempt_total"])
	require.Equal(t, float64(rounds*4), values["bifroest_authentication_attempts_total"])
}

func TestMonitoringBoundedHTTP2CancellationAndBudgetDrain(t *testing.T) {
	f := newWebSocketFixture(t, webSocketWaitTask, enableMonitoringTest)
	m := f.svc.monitoring
	defer monitoringLoadScraper(t, m)()
	token := f.login(t)
	const rounds, streams = 3, webMaximumWorkersPerPeer
	for range rounds {
		cancels := make([]context.CancelFunc, 0, streams)
		bodies := make([]*io.PipeWriter, 0, streams)
		done := make(chan error, streams)
		for range streams {
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(t.Context())
			cancels = append(cancels, cancel)
			bodies = append(bodies, writer)
			t.Cleanup(func() { cancel(); _ = reader.Close(); _ = writer.Close() })
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://app.example.org"+webAPI+"access", reader)
			require.NoError(t, err)
			request.Header.Set("Origin", "https://app.example.org")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+token)
			go func() {
				response, err := f.client.Do(request)
				if response != nil {
					_ = response.Body.Close()
				}
				done <- err
			}()
		}
		require.Eventually(t, func() bool {
			f.svc.web.mutex.Lock()
			workers := f.svc.web.active
			f.svc.web.mutex.Unlock()
			return workers == streams && monitoringLoadSnapshot(t, m)["bifroest_http_requests_active"] == streams
		}, 2*time.Second, 10*time.Millisecond)
		// One extra request must be rejected, not treated as a failed login.
		request, err := http.NewRequest(http.MethodPost, "https://app.example.org"+webAPI+"access", strings.NewReader(`{"slug":"Work"}`))
		require.NoError(t, err)
		request.Header.Set("Origin", "https://app.example.org")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := f.client.Do(request)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		_ = response.Body.Close()
		require.Equal(t, 2, response.ProtoMajor)
		require.Equal(t, http.StatusTooManyRequests, response.StatusCode)
		for _, cancel := range cancels {
			cancel()
		}
		for _, body := range bodies {
			_ = body.Close()
		}
		for range streams {
			select {
			case err := <-done:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP/2 cancellation did not release its client")
			}
		}
		requireMonitoringLoadDrained(t, m, false)
		f.svc.web.mutex.Lock()
		workers := f.svc.web.active
		f.svc.web.mutex.Unlock()
		require.Zero(t, workers)
	}
	values := monitoringLoadSnapshot(t, m)
	require.Equal(t, 1.0, values["bifroest_authentication_attempts_total"])
	require.Equal(t, float64(rounds), values["bifroest_http_rejections_total"])
	require.Equal(t, 1.0, values["bifroest_http_connections_opened_total"], "canceling streams must not require replacing the shared HTTP/2 socket")
	f.client.CloseIdleConnections()
	requireMonitoringLoadDrained(t, m, true)
}

func TestMonitoringBoundedWebSocketChurnAndRejectionDrain(t *testing.T) {
	f := newWebSocketFixture(t, webSocketWaitTask, enableMonitoringTest, func(conf *configuration.Configuration) { conf.Session.V.(*configuration.SessionFs).MaxConnections = 16 })
	m := f.svc.monitoring
	defer monitoringLoadScraper(t, m)()
	token := f.login(t)
	f.client.CloseIdleConnections()
	requireMonitoringLoadDrained(t, m, true)
	const rounds, sockets = 2, webTerminalMaximumSocketsPerPeer
	for range rounds {
		connections := make([]*websocket.Conn, 0, sockets)
		for range sockets {
			conn := f.dial(t)
			connections = append(connections, conn)
			require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
			requireWebSocketReady(t, conn)
		}
		require.Eventually(t, func() bool {
			values := monitoringLoadSnapshot(t, m)
			return values["bifroest_tasks_active"] == sockets && values["bifroest_session_connections_active"] == sockets && values["bifroest_http_channels_active"] == sockets
		}, 2*time.Second, 10*time.Millisecond)
		rejected, response, err := f.dialer.Dial("wss://app.example.org"+webAPI+"terminal", http.Header{"Origin": []string{"https://app.example.org"}})
		if rejected != nil {
			_ = rejected.Close()
		}
		require.Error(t, err)
		require.NotNil(t, response)
		_ = response.Body.Close()
		require.Equal(t, http.StatusTooManyRequests, response.StatusCode)
		for index, conn := range connections {
			if index%2 == 0 {
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			}
			require.NoError(t, conn.Close())
		}
		requireMonitoringLoadDrained(t, m, true)
	}
	// A failed in-channel grant check is not another authentication attempt.
	conn := f.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen("invalid-grant")))
	require.Equal(t, `"authentication-denied"`, string(webSocketStatus(t, conn)["code"]))
	_ = conn.Close()
	requireMonitoringLoadDrained(t, m, true)
	values := monitoringLoadSnapshot(t, m)
	require.Equal(t, 1.0, values["bifroest_authentication_attempts_total"])
	require.Equal(t, float64(rounds), values["bifroest_connections_rejected_total"])
	require.Equal(t, float64(rounds*sockets+1), values["bifroest_http_channels_opened_total"])
	require.Equal(t, values["bifroest_http_connections_opened_total"], values["bifroest_http_connections_closed_total"])
}

func TestMonitoringBoundedTunnelAbortsDrain(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) { enableMonitoringTest(conf); conf.Ssh.MaxStartupsFull = 0 })
			m := f.svc.monitoring
			defer monitoringLoadScraper(t, m)()
			const rounds, tunnels = 3, 4
			for range rounds {
				connections := make([]net.Conn, 0, tunnels)
				for range tunnels {
					connections = append(connections, f.transportConn(t, mode))
				}
				require.Eventually(t, func() bool {
					values := monitoringLoadSnapshot(t, m)
					return values["bifroest_connections_unauthenticated"] == tunnels && values["bifroest_http_channels_active"] == tunnels
				}, 2*time.Second, 10*time.Millisecond)
				for _, conn := range connections {
					require.NoError(t, conn.Close())
				}
				requireMonitoringLoadDrained(t, m, false)
			}
			f.cancel()
			require.NoError(t, f.await())
			requireMonitoringLoadDrained(t, m, true)
			values := monitoringLoadSnapshot(t, m)
			require.Equal(t, float64(rounds*tunnels), values["bifroest_connections_closed_without_authentication_attempt_total"])
			require.Zero(t, values["bifroest_authentication_attempts_total"])
			require.Equal(t, values["bifroest_http_connections_opened_total"], values["bifroest_http_connections_closed_total"])
		})
	}
}

func TestMonitoringBoundedHandshakeTimeoutsDrain(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		enableMonitoringTest(conf)
		conf.Ssh.HandshakeTimeout = common.DurationOf(150 * time.Millisecond)
		conf.Ssh.MaxStartupsFull = 0
	})
	const connections = 6
	for range connections {
		conn, err := net.DialTimeout("tcp", server.address, time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
	}
	m := server.service.monitoring
	require.Eventually(t, func() bool {
		return monitoringLoadSnapshot(t, m)["bifroest_connections_closed_without_authentication_attempt_total"] == connections
	}, 3*time.Second, 10*time.Millisecond)
	requireMonitoringLoadDrained(t, m, true)
	require.Equal(t, float64(connections), monitoringLoadSnapshot(t, m)["bifroest_connections_closed_without_authentication_attempt_total"])
	require.Equal(t, float64(connections), testutil.ToFloat64(m.access.withoutAttempt.WithLabelValues("timeout")))
	require.Zero(t, monitoringLoadSnapshot(t, m)["bifroest_authentication_attempts_total"])
}
