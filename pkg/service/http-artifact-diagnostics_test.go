package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
)

type artifactAuditTiming struct {
	name   string
	start  time.Time
	end    time.Time
	failed bool
}

type artifactTimedRecorder struct {
	audit.Recorder
	mutex   sync.Mutex
	timings []*artifactAuditTiming
}

func (r *artifactTimedRecorder) Record(ctx context.Context, event audit.Event) error {
	entry := &artifactAuditTiming{name: string(event.Name), start: time.Now()}
	r.mutex.Lock()
	r.timings = append(r.timings, entry)
	if len(r.timings) > 64 {
		r.timings = r.timings[len(r.timings)-64:]
	}
	r.mutex.Unlock()
	err := r.Recorder.Record(ctx, event)
	r.mutex.Lock()
	entry.end, entry.failed = time.Now(), err != nil
	r.mutex.Unlock()
	return err
}

type artifactTraceTransport struct {
	http.RoundTripper
	report func(string, ...any)
	audit  *artifactTimedRecorder
}

func (r *artifactTraceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	started := time.Now()
	var connected, reused, tlsReady, wrote, firstByte atomic.Bool
	trace := &httptrace.ClientTrace{
		GotConn:              func(info httptrace.GotConnInfo) { connected.Store(true); reused.Store(info.Reused) },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { tlsReady.Store(true) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote.Store(true) },
		GotFirstResponseByte: func() { firstByte.Store(true) },
	}
	response, err := r.RoundTripper.RoundTrip(request.WithContext(httptrace.WithClientTrace(request.Context(), trace)))
	if err != nil {
		r.report("artifact request stage: path=%s elapsed=%v connected=%v reused=%v tls=%v wrote=%v firstByte=%v", request.URL.Path, time.Since(started), connected.Load(), reused.Load(), tlsReady.Load(), wrote.Load(), firstByte.Load())
		r.audit.mutex.Lock()
		for _, timing := range r.audit.timings {
			if strings.HasPrefix(timing.name, "authentication.") || strings.HasPrefix(timing.name, "session.") || strings.HasPrefix(timing.name, "management.") {
				elapsed := timing.end.Sub(timing.start)
				if timing.end.IsZero() {
					elapsed = time.Since(timing.start)
				}
				r.report("artifact audit stage: name=%s elapsed=%v done=%v failed=%v", timing.name, elapsed, !timing.end.IsZero(), timing.failed)
			}
		}
		r.audit.mutex.Unlock()
		stack := make([]byte, 256<<10)
		stack = stack[:runtime.Stack(stack, true)]
		seen := make(map[string]bool)
		for _, line := range strings.Split(string(stack), "\n") {
			if strings.HasPrefix(line, "github.com/engity-com/bifroest/") || strings.HasPrefix(line, "filippo.io/") || strings.HasPrefix(line, "golang.org/x/crypto/") || strings.HasPrefix(line, "os.(*File).Sync") || strings.HasPrefix(line, "internal/poll.(*FD).Fsync") {
				if index := strings.LastIndex(line, "("); index >= 0 {
					line = line[:index]
				}
				if seen[line] || len(seen) >= 128 {
					continue
				}
				seen[line] = true
				r.report("artifact pending function: %s", line)
			}
		}
	}
	return response, err
}

type artifactDiagnosticFailureTransport struct{}

func (artifactDiagnosticFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

func TestArtifactRequestFailureDiagnosticsDoNotExposeCredentialsOrBodies(t *testing.T) {
	const secret = "PRIVATE-DIAGNOSTIC-SENTINEL"
	var logs []string
	transport := &artifactTraceTransport{
		RoundTripper: artifactDiagnosticFailureTransport{},
		report:       func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
		audit:        &artifactTimedRecorder{},
	}
	request, err := http.NewRequest(http.MethodPost, "https://app.example.org/api/v1/management/flows/list?private="+secret, strings.NewReader(secret))
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Cookie", "private="+secret)
	response, err := transport.RoundTrip(request)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, response)
	require.NoError(t, request.Body.Close())
	output := strings.Join(logs, "\n")
	require.NotContains(t, output, secret)
	require.NotContains(t, output, "Authorization")
	require.NotContains(t, output, "Cookie")
	require.Contains(t, output, "path=/api/v1/management/flows/list")
	require.NotContains(t, output, "?private=")
	for _, line := range logs {
		if strings.HasPrefix(line, "artifact pending function:") {
			require.NotContains(t, line, "0x", "function arguments must never be logged")
		}
	}
}

func TestArtifactTimedRecorderDelegatesAndRetainsOnlyBoundedPhaseData(t *testing.T) {
	delegate := &recordingAuditRecorder{}
	recorder := &artifactTimedRecorder{Recorder: delegate}
	for range 100 {
		require.NoError(t, recorder.Record(t.Context(), audit.Event{Name: audit.EventNameSessionTaskCompleted, Reason: "PRIVATE-EVENT-SENTINEL"}))
	}
	require.Len(t, delegate.eventsSnapshot(), 100, "phase collection must never replace or suppress audit delegation")
	require.Len(t, recorder.timings, 64)
	for _, phase := range recorder.timings {
		require.Equal(t, string(audit.EventNameSessionTaskCompleted), phase.name)
		require.False(t, phase.start.IsZero())
		require.False(t, phase.end.IsZero())
		require.False(t, phase.failed)
	}
	require.NoError(t, recorder.Close())
}
