package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
)

// Ages are a snapshot of live objects, not a histogram of completed lifetimes.
type monitoringAges struct {
	count                 int
	sum, youngest, oldest float64
}

func (a *monitoringAges) add(created, now time.Time) {
	if created.IsZero() {
		return
	}
	age := max(0, now.Sub(created).Seconds())
	if a.count == 0 || age < a.youngest {
		a.youngest = age
	}
	if age > a.oldest {
		a.oldest = age
	}
	a.count++
	a.sum += age
}

type monitoringAccess struct {
	mutex                                                   sync.Mutex
	ssh                                                     map[*connection]struct{}
	attempts, rejected, withoutAttempt, denials, suppressed *prometheus.CounterVec
}

func (m *serviceMonitoring) initAccess() {
	m.access.ssh = make(map[*connection]struct{})
	m.access.attempts = m.counterVec(prometheus.CounterOpts{Name: "bifroest_authentication_attempts_total", Help: "Authentication attempt results, once per attempt, never once per evaluated flow. Public-key eligibility is not success."}, append(append([]string{}, monitoringFlowLabels...), "transport", "method", "result"))
	m.access.rejected = m.counterVec(prometheus.CounterOpts{Name: "bifroest_connections_rejected_total", Help: "Connection or channel admissions rejected by protection limits."}, []string{"transport", "reason"})
	m.access.withoutAttempt = m.counterVec(prometheus.CounterOpts{Name: "bifroest_connections_closed_without_authentication_attempt_total", Help: "SSH connections closed without any offered authentication method other than none."}, []string{"reason"})
	m.access.denials = m.counterVec(prometheus.CounterOpts{Name: "bifroest_access_denials_total", Help: "Post-login action denials observed at policy decision producers, independently of audit persistence."}, append(append([]string{}, monitoringFlowLabels...), "operation", "reason"))
	m.access.suppressed = m.counterVec(prometheus.CounterOpts{Name: "bifroest_auditlog_details_suppressed_total", Help: "Unauthenticated audit details aggregated or suppressed by rate limits or journal reserve."}, []string{"auditlog", "reason"})
	m.registry.MustRegister(m.access.attempts, m.access.rejected, m.access.withoutAttempt, m.access.denials, m.access.suppressed)
	for _, name := range []string{"sessions", "session_connections"} {
		for _, stat := range []string{"count", "sum", "oldest", "youngest", "average"} {
			key := monitoringAgeMetricName(name, stat)
			m.descriptions[key] = prometheus.NewDesc("bifroest_"+key, "Age snapshot of active "+name+"; count includes only known creation times.", monitoringFlowLabels, nil)
		}
	}
	for _, stat := range []string{"count", "sum", "oldest", "youngest", "average"} {
		key := monitoringAgeMetricName("connections", stat)
		m.descriptions[key] = prometheus.NewDesc("bifroest_"+key, "Age snapshot of physical HTTP/TLS or logical SSH connections; SSH tunnels also own an HTTP transport.", []string{"transport"}, nil)
	}
	m.descriptions["connections_unauthenticated"] = prometheus.NewDesc("bifroest_connections_unauthenticated", "Open SSH connections without a successful authentication result.", nil, nil)
}

func emitMonitoringAges(ch chan<- prometheus.Metric, descriptions map[string]*prometheus.Desc, prefix string, a monitoringAges, labels ...string) {
	emit := func(stat string, value float64) {
		ch <- prometheus.MustNewConstMetric(descriptions[monitoringAgeMetricName(prefix, stat)], prometheus.GaugeValue, value, labels...)
	}
	emit("count", float64(a.count))
	emit("sum", a.sum)
	if a.count > 0 {
		emit("oldest", a.oldest)
		emit("youngest", a.youngest)
		emit("average", a.sum/float64(a.count))
	}
}

func monitoringAgeMetricName(prefix, stat string) string {
	switch stat {
	case "count":
		return prefix + "_age_observations"
	case "sum":
		return prefix + "_age_sum_seconds"
	default:
		return prefix + "_" + stat + "_age_seconds"
	}
}

func (m *serviceMonitoring) collectAccess(ch chan<- prometheus.Metric, svc *service) {
	now := time.Now()
	var ages monitoringAges
	unauthenticated := 0
	m.access.mutex.Lock()
	for c := range m.access.ssh {
		if c.IsClosed() {
			continue
		}
		ages.add(c.createdAt, now)
		if !c.authenticated.Load() {
			unauthenticated++
		}
	}
	m.access.mutex.Unlock()
	emitMonitoringAges(ch, m.descriptions, "connections", ages, "ssh")
	ch <- prometheus.MustNewConstMetric(m.descriptions["connections_unauthenticated"], prometheus.GaugeValue, float64(unauthenticated))
	snapshots := svc.sessionConnections.monitoringAges(now)
	for flow := range m.flows {
		snapshot := snapshots[flow]
		emitMonitoringAges(ch, m.descriptions, "sessions", snapshot[0], m.flowLabels(flow)...)
		emitMonitoringAges(ch, m.descriptions, "session_connections", snapshot[1], m.flowLabels(flow)...)
	}
}

func (m *serviceMonitoring) connectionOpened(c *connection) {
	if m == nil {
		return
	}
	m.access.mutex.Lock()
	m.access.ssh[c] = struct{}{}
	m.access.mutex.Unlock()
}

func (m *serviceMonitoring) connectionClosed(c *connection) {
	if m == nil {
		return
	}
	m.access.mutex.Lock()
	delete(m.access.ssh, c)
	m.access.mutex.Unlock()
}

func (m *serviceMonitoring) connectionFinished(c *connection) {
	if m == nil || !c.monitoringFinished.CompareAndSwap(false, true) {
		return
	}
	if !c.authenticationAttempted.Load() {
		m.access.withoutAttempt.WithLabelValues(monitoringCloseReason(c.monitoringEnd.Load())).Inc()
	}
}

// Stable classifications only. Neither raw errors nor peer-provided text become labels.
func monitoringEndReason(err error) uint32 {
	if err == nil {
		return 0
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return 1
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return 2
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return 3
	}
	return 4
}
func monitoringCloseReason(reason uint32) string {
	switch reason {
	case 1:
		return "timeout"
	case 2:
		return "peer_closed"
	case 3:
		return "closed"
	case 4:
		return "protocol_error"
	default:
		return "closed"
	}
}

func (m *serviceMonitoring) authenticationAttempt(flow configuration.FlowName, transport, method, result string) {
	if m == nil {
		return
	}
	method = monitoringValue(method, "public-key", "password", "keyboard-interactive", "browser-remember-me")
	m.access.attempts.WithLabelValues(append(append([]string{}, m.flowLabels(flow)...), monitoringValue(transport, "ssh", "http"), method, monitoringValue(result, "success", "denied", "error", "abandoned"))...).Inc()
}

func monitoringAuthenticationResult(err error) string {
	if err == nil {
		return "success"
	}
	if berrors.IsType(err, berrors.System) || berrors.IsType(err, berrors.Config) || berrors.IsType(err, berrors.Network) {
		return "error"
	}
	return "denied"
}

func monitoringBrowserAuthenticationResult(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "abandoned"
	}
	if berrors.IsType(err, berrors.User) || berrors.IsType(err, berrors.Permission) || berrors.IsType(err, berrors.Expired) || errors.Is(err, errWebKeyProof) {
		return "denied"
	}
	// Browser adapters retain the original provider error. Unlike SSH's final
	// AuthLog callback, an untyped error here is not the generic credential denial.
	return "error"
}

func (m *serviceMonitoring) reject(transport, reason string) {
	if m != nil {
		m.access.rejected.WithLabelValues(monitoringValue(transport, "ssh", "http", "terminal", "management", "ssh_tunnel"), monitoringValue(reason, "connections", "session_connections", "startups", "channels", "channels_per_connection", "sessions_per_connection", "reverse_forwards", "reverse_forwards_per_connection", "workers", "peer_workers", "peers", "request_rate", "login_rate", "login_capacity", "sockets", "peer_sockets", "stopping")).Inc()
	}
}

func (m *serviceMonitoring) sshLimitRejected(transport string, reason essh.LimitRejectionReason) {
	label := "unknown"
	switch reason {
	case essh.LimitRejectionMaxStartups:
		label = "startups"
	case essh.LimitRejectionMaxConnections:
		label = "connections"
	case essh.LimitRejectionMaxChannels:
		label = "channels"
	case essh.LimitRejectionMaxChannelsPerConnection:
		label = "channels_per_connection"
	case essh.LimitRejectionMaxSessionsPerConnection:
		label = "sessions_per_connection"
	case essh.LimitRejectionMaxReverseForwards:
		label = "reverse_forwards"
	case essh.LimitRejectionMaxReverseForwardsPerConnection:
		label = "reverse_forwards_per_connection"
	}
	m.reject(transport, label)
}

func (m *serviceMonitoring) suppress(name configuration.AuditlogName, reason string) {
	if m != nil {
		m.access.suppressed.WithLabelValues(name.String(), monitoringValue(reason, "rate_limit", "journal_reserve")).Inc()
	}
}

func (m *serviceMonitoring) accessDecision(flow configuration.FlowName, event audit.Event) {
	if m == nil || event.Outcome != audit.EventOutcomeDenied {
		return
	}
	operation := monitoringValue(string(event.Name), audit.EventNameSessionPtyDecided, audit.EventNameSessionAgentForwardingDecided, audit.EventNamePortForwardingDirectDecided, audit.EventNamePortForwardingReverseDecided, audit.EventNameSessionTaskCompleted)
	if operation == "unknown" {
		return
	}
	m.deny(flow, operation, string(event.Reason))
}

func (m *serviceMonitoring) deny(flow configuration.FlowName, operation, reason string) {
	if m == nil {
		return
	}
	operation = monitoringValue(operation, audit.EventNameSessionPtyDecided, audit.EventNameSessionAgentForwardingDecided, audit.EventNamePortForwardingDirectDecided, audit.EventNamePortForwardingReverseDecided, audit.EventNameSessionTaskCompleted, "subsystem", "management")
	m.access.denials.WithLabelValues(append(append([]string{}, m.flowLabels(flow)...), operation, monitoringValue(reason, "authorized-key-policy", "environment-policy", "invalid-request", "session-incompatible", "destination-rejected", "invalid-bind", "policy"))...).Inc()
}

// Browser attempt control requests (poll/reply) are not separate logins. One
// completion gate also handles expiry, cancellation and unclaimed results.
type monitoringLoginAttempt struct {
	once    sync.Once
	monitor *serviceMonitoring
	method  string
}

func (m *serviceMonitoring) loginAttempt(method audit.AuthenticationMethod) *monitoringLoginAttempt {
	if m == nil {
		return nil
	}
	return &monitoringLoginAttempt{monitor: m, method: string(method)}
}
func (a *monitoringLoginAttempt) finish(flow configuration.FlowName, result string) {
	if a == nil {
		return
	}
	a.once.Do(func() { a.monitor.authenticationAttempt(flow, "http", a.method, result) })
}
