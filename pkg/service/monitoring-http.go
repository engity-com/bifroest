package service

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/webui"
)

type monitoringHTTP struct {
	mutex            sync.Mutex
	connections      map[*monitoringHTTPConnection]time.Time
	opened           prometheus.Counter
	closed           *prometheus.CounterVec
	handshakes       *prometheus.CounterVec
	requests         *prometheus.CounterVec
	input            *prometheus.CounterVec
	output           *prometheus.CounterVec
	rejections       *prometheus.CounterVec
	channelOpened    *prometheus.CounterVec
	channelClosed    *prometheus.CounterVec
	channelFailures  *prometheus.CounterVec
	active           *prometheus.GaugeVec
	channelActive    *prometheus.GaugeVec
	duration         *prometheus.HistogramVec
	channelDuration  *prometheus.HistogramVec
	transferDuration *prometheus.HistogramVec
	renewalErrors    prometheus.Counter
}
type monitoringHTTPConnection struct {
	complete, closed bool
	reason           string
}
type monitoringRequestKey struct{}
type monitoringRequest struct {
	monitor   *serviceMonitoring
	flow      atomic.Pointer[configuration.FlowName]
	streaming atomic.Bool
	transfer  atomic.Bool
}

func (m *serviceMonitoring) initHTTP() {
	h := &m.http
	h.connections = make(map[*monitoringHTTPConnection]time.Time)
	h.opened = prometheus.NewCounter(prometheus.CounterOpts{Name: "bifroest_http_connections_opened_total", Help: "Accepted physical workload HTTP/TLS sockets, not HTTP/2 streams or logical SSH transports."})
	h.closed = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_connections_closed_total", Help: "Closed physical HTTP/TLS sockets, including hijacked WebSockets."}, []string{"reason"})
	h.handshakes = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_tls_handshakes_total", Help: "TLS connection outcomes: established application connections or sockets closed before application readiness."}, []string{"result", "reason"})
	labels := []string{"route", "method", "status", "flow"}
	h.requests = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_requests_total", Help: "Workload HTTP requests that reached net/http's handler, including boundary rejections."}, labels)
	h.input = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_request_body_bytes_total", Help: "Read HTTP request body bytes, excluding WebSocket frames and TLS/framing overhead."}, labels)
	h.output = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_response_body_bytes_total", Help: "Written HTTP response body bytes, excluding hijacked WebSocket frames and TLS/framing overhead."}, labels)
	h.active = m.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_http_requests_active", Help: "Currently executing workload HTTP handlers, including streaming handlers."}, []string{"route", "method"})
	h.duration = m.histogramVec(prometheus.HistogramOpts{Name: "bifroest_http_request_duration_seconds", Help: "Non-streaming HTTP handler duration. Successfully opened WebSockets/tunnels are excluded."}, labels)
	h.transferDuration = m.histogramVec(prometheus.HistogramOpts{Name: "bifroest_http_transfer_duration_seconds", Help: "Dedicated HTTP artifact transfer duration, excluding WebSocket transfers and ordinary API latency.", Buckets: []float64{.1, 1, 5, 15, 60, 300, 1800}}, labels)
	h.rejections = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_rejections_total", Help: "Workload HTTP security and protection-budget rejections at their decision points."}, []string{"route", "reason"})
	h.channelOpened = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_channels_opened_total", Help: "Opened WebSockets or full-duplex SSH streams, before in-channel authentication."}, []string{"kind"})
	h.channelActive = m.gaugeVec(prometheus.GaugeOpts{Name: "bifroest_http_channels_active", Help: "Open WebSockets and full-duplex SSH streams, not physical sockets or SSH channels."}, []string{"kind"})
	h.channelClosed = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_channels_closed_total", Help: "Closed WebSockets and SSH streams with bounded termination reasons."}, []string{"kind", "reason"})
	h.channelFailures = m.counterVec(prometheus.CounterOpts{Name: "bifroest_http_channel_open_failures_total", Help: "HTTP requests to channel routes that did not open a channel."}, []string{"kind", "status"})
	h.channelDuration = m.histogramVec(prometheus.HistogramOpts{Name: "bifroest_http_channel_duration_seconds", Help: "Opened channel lifetimes, separate from normal API latency.", Buckets: []float64{1, 5, 15, 60, 300, 1800, 7200, 86400}}, []string{"kind"})
	h.renewalErrors = prometheus.NewCounter(prometheus.CounterOpts{Name: "bifroest_http_tls_renewal_errors_total", Help: "Failed existing workload HTTP certificate renewal rounds."})
	m.registry.MustRegister(h.opened, h.closed, h.handshakes, h.requests, h.input, h.output, h.active, h.duration, h.rejections, h.channelOpened, h.channelActive, h.channelClosed, h.channelFailures, h.channelDuration, h.renewalErrors)
	m.registry.MustRegister(h.transferDuration)
	m.descriptions["http_connections_active"] = prometheus.NewDesc("bifroest_http_connections_active", "Open physical workload HTTP/TLS sockets, including hijacks.", nil, nil)
	m.descriptions["http_tls_certificate_expiration_timestamp_seconds"] = prometheus.NewDesc("bifroest_http_tls_certificate_expiration_timestamp_seconds", "Expiry of the currently published workload HTTP certificate for a configured domain.", []string{"domain"}, nil)
}

func (m *serviceMonitoring) httpConnectionOpened() https.ConnectionObservation {
	h := &m.http
	state := &monitoringHTTPConnection{}
	h.mutex.Lock()
	h.connections[state] = time.Now()
	h.mutex.Unlock()
	h.opened.Inc()
	return func(event string) {
		h.mutex.Lock()
		defer h.mutex.Unlock()
		switch event {
		case "handshake_complete":
			if !state.complete {
				state.complete = true
				h.handshakes.WithLabelValues("success", "").Inc()
			}
		case "timeout", "peer_closed", "io_error":
			if state.reason == "" {
				state.reason = event
			}
		case "closed":
			if state.closed {
				return
			}
			state.closed = true
			delete(h.connections, state)
			reason := state.reason
			if reason == "" {
				reason = "closed"
			}
			h.closed.WithLabelValues(reason).Inc()
		case "handshake_aborted":
			if !state.complete {
				state.complete = true
				reason := state.reason
				if reason == "" {
					reason = "protocol_error"
				}
				h.handshakes.WithLabelValues("aborted", reason).Inc()
			}
		}
	}
}

func (m *serviceMonitoring) collectHTTP(ch chan<- prometheus.Metric, svc *service) {
	var ages monitoringAges
	m.http.mutex.Lock()
	for _, at := range m.http.connections {
		ages.add(at, time.Now())
	}
	count := len(m.http.connections)
	m.http.mutex.Unlock()
	ch <- prometheus.MustNewConstMetric(m.descriptions["http_connections_active"], prometheus.GaugeValue, float64(count))
	emitMonitoringAges(ch, m.descriptions, "connections", ages, "http")
	if svc.https != nil {
		for domain, expires := range svc.https.CertificateExpirations() {
			ch <- prometheus.MustNewConstMetric(m.descriptions["http_tls_certificate_expiration_timestamp_seconds"], prometheus.GaugeValue, float64(expires.Unix()), domain)
		}
	}
}

// Only source-code routes/groups are returned. Never derive a label from a URL
// suffix, query, authority, Origin or peer-supplied method/status text.
func monitoringHTTPRoute(path string) string {
	switch path {
	case "/":
		return "document"
	case "/login", "/login/", configuration.OidcCallbackPath:
		return "oidc_document"
	case webAPI + "ssh":
		return "ssh_tunnel"
	case webAPI + "terminal":
		return "terminal"
	case webAPI + "management/channel":
		return "management_channel"
	case webAPI + "discovery":
		return "discovery"
	case webAPI + "oidc/start", webAPI + "oidc/status", webAPI + "oidc/callback", webAPI + "oidc/approve", webAPI + "oidc/deny":
		return strings.TrimPrefix(path, webAPI)
	case webAPI + "login/password", webAPI + "login/interactive", webAPI + "login/oidc", webAPI + "login/public-key", webAPI + "login/poll", webAPI + "login/reply", webAPI + "login/cancel",
		webAPI + "remember/enroll", webAPI + "remember/resume", webAPI + "remember/revoke", webAPI + "remember/prove", webAPI + "access", webAPI + "logout",
		webAPI + "management/flows/list", webAPI + "management/sessions/list", webAPI + "management/sessions/show", webAPI + "management/auditlogs/list", webAPI + "management/recordings/list", webAPI + "management/audit-events/list", webAPI + "management/recordings/verify", webAPI + "management/version/show", webAPI + "management/sessions/prepare", webAPI + "management/sessions/confirm", webAPI + "management/sessions/cancel", webAPI + "management/artifacts/recording", webAPI + "management/artifacts/audit", webAPI + "management/artifacts/recordings":
		return strings.TrimPrefix(path, webAPI)
	}
	if strings.HasPrefix(path, webui.Prefix) || strings.HasPrefix(path, webui.CustomPrefix) {
		return "assets"
	}
	return "unknown"
}

func monitoringChannelKind(route string) string {
	switch route {
	case "terminal":
		return "terminal"
	case "management_channel":
		return "management"
	case "ssh_tunnel":
		return "ssh_tunnel"
	default:
		return ""
	}
}

type monitoringBody struct {
	io.ReadCloser
	bytes atomic.Int64
}

func (b *monitoringBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}

func (m *serviceMonitoring) observeHTTPRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := "unknown"
		if r.URL != nil {
			route = monitoringHTTPRoute(r.URL.Path)
		}
		method := monitoringValue(r.Method, "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE")
		active := m.http.active.WithLabelValues(route, method)
		active.Inc()
		defer active.Dec()
		observation := &monitoringRequest{monitor: m}
		r = r.WithContext(context.WithValue(r.Context(), monitoringRequestKey{}, observation))
		body := &monitoringBody{ReadCloser: r.Body}
		r.Body = body
		var status atomic.Int32
		var bytes atomic.Int64
		started := time.Now()
		hooks := httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					if code >= 200 || code == 101 {
						status.CompareAndSwap(0, int32(code))
					}
					next(code)
				}
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(p []byte) (int, error) {
					status.CompareAndSwap(0, 200)
					n, err := next(p)
					bytes.Add(int64(n))
					return n, err
				}
			},
			WriteString: func(next httpsnoop.WriteStringFunc) httpsnoop.WriteStringFunc {
				return func(value string) (int, error) {
					status.CompareAndSwap(0, 200)
					n, err := next(value)
					bytes.Add(int64(n))
					return n, err
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(reader io.Reader) (int64, error) {
					status.CompareAndSwap(0, 200)
					n, err := next(reader)
					bytes.Add(n)
					return n, err
				}
			},
			Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return func() { status.CompareAndSwap(0, 200); next() }
			},
			FlushError: func(next httpsnoop.FlushErrorFunc) httpsnoop.FlushErrorFunc {
				return func() error { status.CompareAndSwap(0, 200); return next() }
			},
			Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
				return func() (net.Conn, *bufio.ReadWriter, error) {
					c, rw, err := next()
					if err == nil {
						status.CompareAndSwap(0, 101)
					}
					return c, rw, err
				}
			},
		}
		defer func() {
			code := status.Load()
			if code == 0 {
				code = 200
			}
			statusLabel := "unknown"
			if code >= 100 && code <= 599 {
				statusLabel = strconv.Itoa(int(code))
			}
			var knownFlow configuration.FlowName
			if value := observation.flow.Load(); value != nil {
				knownFlow = *value
			}
			flow := m.flowLabels(knownFlow)[0]
			labels := []string{route, method, statusLabel, flow}
			m.http.requests.WithLabelValues(labels...).Inc()
			m.http.input.WithLabelValues(labels...).Add(float64(body.bytes.Load()))
			m.http.output.WithLabelValues(labels...).Add(float64(bytes.Load()))
			if !observation.streaming.Load() {
				if observation.transfer.Load() {
					m.http.transferDuration.WithLabelValues(labels...).Observe(time.Since(started).Seconds())
				} else {
					m.http.duration.WithLabelValues(labels...).Observe(time.Since(started).Seconds())
				}
				if kind := monitoringChannelKind(route); kind != "" {
					m.http.channelFailures.WithLabelValues(kind, statusLabel).Inc()
				}
			}
		}()
		next.ServeHTTP(httpsnoop.Wrap(w, hooks), r)
	})
}

func (m *serviceMonitoring) httpRejected(r *http.Request, reason string) {
	if m == nil {
		return
	}
	route := "unknown"
	if r.URL != nil {
		route = monitoringHTTPRoute(r.URL.Path)
	}
	m.http.rejections.WithLabelValues(route, monitoringValue(reason, "transport", "authority", "path", "origin", "csrf", "body_limit", "socket_budget", "wire_budget", "message_budget", "stopping", "peers", "workers", "peer_workers", "request_rate", "login_rate", "login_capacity")).Inc()
}

func monitoringHTTPFlow(ctx context.Context, flow configuration.FlowName) {
	if observation, _ := ctx.Value(monitoringRequestKey{}).(*monitoringRequest); observation != nil {
		observation.flow.Store(&flow)
	}
}

func (m *serviceMonitoring) channelOpened(r *http.Request, kind string) func(string) {
	if m == nil {
		return func(string) {}
	}
	if observation, _ := r.Context().Value(monitoringRequestKey{}).(*monitoringRequest); observation != nil {
		observation.streaming.Store(true)
	}
	kind = monitoringValue(kind, "terminal", "management", "ssh_tunnel")
	m.http.channelOpened.WithLabelValues(kind).Inc()
	active := m.http.channelActive.WithLabelValues(kind)
	active.Inc()
	started := time.Now()
	var once sync.Once
	return func(reason string) {
		once.Do(func() {
			active.Dec()
			m.http.channelClosed.WithLabelValues(kind, monitoringValue(reason, "closed", "peer_closed", "timeout", "protocol_error", "authentication_denied", "connection_denied", "error", "shutdown", "completed")).Inc()
			m.http.channelDuration.WithLabelValues(kind).Observe(time.Since(started).Seconds())
		})
	}
}
