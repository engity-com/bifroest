package service

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestUnauthenticatedAuditLimiterBoundsPerSourceAndGlobally(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 2, 3)
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Domain: audit.EventDomainAuthentication, Outcome: audit.EventOutcomeDenied}

	for range 3 {
		require.NoError(t, limiter.Record(limiterTestContext("192.0.2.1"), "security", true, recorder, event))
	}
	for range 2 {
		require.NoError(t, limiter.Record(limiterTestContext("192.0.2.2"), "security", true, recorder, event))
	}
	require.NoError(t, limiter.Flush(context.Background()))

	events := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(events, audit.EventNameAuthenticationFlowEvaluated), 3)
	summaries := auditEventsNamed(events, audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, summaries, 2)
	require.Equal(t, uint64(1), *summaries[0].Count)
	require.Equal(t, uint64(1), *summaries[1].Count)
	for _, summary := range summaries {
		require.Equal(t, audit.EventReasonRateLimit, summary.Reason)
		require.Empty(t, summary.Flow)
		require.Empty(t, summary.ConnectionId)
	}
	payload, err := json.Marshal(summaries)
	require.NoError(t, err)
	require.NotContains(t, string(payload), "192.0.2.")
}

func TestUnauthenticatedAuditLimiterWritesFirstSuppressionImmediatelyAndBoundsSummaries(t *testing.T) {
	now := time.Unix(2_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Domain: audit.EventDomainAuthentication, Outcome: audit.EventOutcomeDenied}
	ctx := limiterTestContext("198.51.100.7")

	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	summaries := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, summaries, 1)
	require.Equal(t, uint64(1), *summaries[0].Count)

	for range 100 {
		require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	}
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed), 1)
	require.NoError(t, limiter.Flush(context.Background()))
	summaries = auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, summaries, 2)
	require.Equal(t, uint64(100), *summaries[1].Count)
}

func TestUnauthenticatedAuditLimiterReserveWritesOneMarkerAndRecovers(t *testing.T) {
	now := time.Unix(3_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	limiter.now = func() time.Time { return now }
	recorder := newLimiterTestRecorder(false)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Domain: audit.EventDomainAuthentication, Outcome: audit.EventOutcomeDenied}
	ctx := limiterTestContext("203.0.113.9")

	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.Len(t, recorder.eventsSnapshot(), 1)
	require.Equal(t, audit.EventReasonJournalReserve, recorder.eventsSnapshot()[0].Reason)

	now = now.Add(time.Minute)
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.Len(t, recorder.eventsSnapshot(), 1, "an attacker must not consume the reserve with repeated markers")

	recorder.setSuppressible(true)
	now = now.Add(time.Minute)
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	events := recorder.eventsSnapshot()
	require.Len(t, events, 3)
	require.Equal(t, audit.EventReasonJournalReserve, events[1].Reason)
	require.Equal(t, uint64(2), *events[1].Count)
	require.Equal(t, audit.EventNameAuthenticationFlowEvaluated, events[2].Name)
}

func TestUnauthenticatedAuditReservePhaseTransitionsPreserveRecorderOrder(t *testing.T) {
	now := time.Unix(3_500, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	recorder := newLimiterTestRecorder(false)
	state := limiter.auditlog("security", recorder)
	state.mutex.Lock()
	defer state.mutex.Unlock()

	enteredReserve, err := limiter.recordRateSummary(context.Background(), state, unauthenticatedAuditSummary(audit.EventOutcomeDenied, audit.EventReasonRateLimit, 1, now, now), now)
	require.NoError(t, err)
	require.True(t, enteredReserve)
	require.Equal(t, reservePhaseMarkerPending, state.reserve.phase)
	require.Equal(t, now.Add(time.Minute), state.reserve.nextCheck)
	require.Equal(t, []string{"record"}, recorder.operationsSnapshot())

	handled, err := limiter.handleReserved(context.Background(), state, now.Add(30*time.Second))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, reservePhaseMonitoring, state.reserve.phase)
	require.Equal(t, now.Add(90*time.Second), state.reserve.nextCheck)
	require.Equal(t, []string{"record", "record"}, recorder.operationsSnapshot())

	handled, err = limiter.handleReserved(context.Background(), state, state.reserve.nextCheck)
	require.NoError(t, err)
	require.False(t, handled)
	require.Equal(t, reservePhaseInactive, state.reserve.phase)
	require.True(t, state.reserve.nextCheck.IsZero())
	require.Equal(t, []string{"record", "record"}, recorder.operationsSnapshot())

	state.reserve.awaitMarker(now.Add(2 * time.Minute))
	handled, err = limiter.handleReserved(context.Background(), state, state.reserve.nextCheck)
	require.NoError(t, err)
	require.False(t, handled)
	require.Equal(t, reservePhaseInactive, state.reserve.phase)
	require.Equal(t, []string{"record", "record"}, recorder.operationsSnapshot())
}

func TestUnauthenticatedAuditLimiterBoundsSourceMapAndNormalizesAddresses(t *testing.T) {
	require.Equal(t, "192.0.2.8", normalizeUnauthenticatedAuditSource(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.8"), Port: 22}))
	require.Equal(t, "2001:db8:1:2::/64", normalizeUnauthenticatedAuditSource(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1234"), Port: 22, Zone: "eth0"}))
	require.Equal(t, "unknown", normalizeUnauthenticatedAuditSource(nil))
	proxyAddress := &net.TCPAddr{IP: net.ParseIP("198.51.100.81"), Port: 41234}
	proxyContext := context.WithValue(context.Background(), essh.ContextKeyRemoteAddr, proxyAddress)
	require.Equal(t, "198.51.100.81", unauthenticatedAuditSourceKey(proxyContext))

	now := time.Unix(4_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, ^uint16(0))
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}
	for index := 0; index <= maxUnauthenticatedAuditSources; index++ {
		address := fmt.Sprintf("2001:db8:%x::1", index)
		require.NoError(t, limiter.Record(limiterTestContext(address), "security", true, recorder, event))
	}
	require.Len(t, limiter.sources, maxUnauthenticatedAuditSources)
}

func TestUnauthenticatedAuditLimiterIsRaceSafe(t *testing.T) {
	now := time.Unix(5_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 4, 16)
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}

	var wait sync.WaitGroup
	errs := make(chan error, 128)
	for index := range 128 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- limiter.Record(limiterTestContext(fmt.Sprintf("192.0.2.%d", index%32)), "security", true, recorder, event)
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, limiter.Flush(context.Background()))
}

func TestUnauthenticatedAuditLimiterDoesNotHoldGlobalMutexDuringRecorderIO(t *testing.T) {
	now := time.Unix(5_250, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 2, 2)
	blocked := newBlockingLimiterTestRecorder()
	fast := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}

	blockedDone := make(chan error, 1)
	go func() {
		blockedDone <- limiter.Record(limiterTestContext("192.0.2.1"), "blocked", true, blocked, event)
	}()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("blocked recorder was not entered")
	}
	t.Cleanup(blocked.unblock)

	fastDone := make(chan error, 1)
	go func() {
		fastDone <- limiter.Record(limiterTestContext("192.0.2.2"), "fast", true, fast, event)
	}()
	select {
	case err := <-fastDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("unrelated auditlog was blocked by recorder I/O")
	}

	blocked.unblock()
	require.NoError(t, <-blockedDone)
}

func TestUnauthenticatedAuditLimiterConcurrentRecordsDoNotBypassRateOrDuplicateCounts(t *testing.T) {
	now := time.Unix(5_375, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 64)
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}

	const attempts = 32
	var wait sync.WaitGroup
	errs := make(chan error, attempts)
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- limiter.Record(limiterTestContext("192.0.2.31"), "security", true, recorder, event)
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, limiter.Flush(context.Background()))

	events := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(events, audit.EventNameAuthenticationFlowEvaluated), 1)
	var suppressed uint64
	for _, summary := range auditEventsNamed(events, audit.EventNameAuthenticationFlowEvaluationsSuppressed) {
		require.Equal(t, audit.EventReasonRateLimit, summary.Reason)
		suppressed += *summary.Count
	}
	require.Equal(t, uint64(attempts-1), suppressed)
}

func TestUnauthenticatedAuditLimiterKeepsRateClassificationWhenReserveStarts(t *testing.T) {
	now := time.Unix(5_425, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	limiter.now = func() time.Time { return now }
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}
	ctx := limiterTestContext("192.0.2.41")

	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	recorder.setSuppressible(false)
	now = now.Add(time.Minute)
	limiter.globalMutex.Lock()
	limiter.global.tokens = 0
	limiter.global.last = now
	limiter.globalMutex.Unlock()
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Flush(context.Background()))

	var rateCount, reserveCount uint64
	for _, summary := range auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed) {
		switch summary.Reason {
		case audit.EventReasonRateLimit:
			require.Equal(t, audit.EventOutcomeDenied, summary.Outcome)
			rateCount += *summary.Count
		case audit.EventReasonJournalReserve:
			require.Empty(t, summary.Outcome)
			reserveCount += *summary.Count
		default:
			t.Fatalf("unexpected suppression reason %q", summary.Reason)
		}
	}
	require.Equal(t, uint64(3), rateCount)
	require.Equal(t, uint64(1), reserveCount)
}

func TestUnauthenticatedAuditLimiterFlushTriesEveryAuditlogAndRetainsFailures(t *testing.T) {
	limiter := newTestUnauthenticatedAuditLimiter(time.Unix(5_450, 0), 1, 1)
	firstFailed := newLimiterTestRecorder(true)
	secondFailed := newLimiterTestRecorder(true)
	healthy := newLimiterTestRecorder(true)
	seedLimiterRateAggregate(limiter, "a-failed", firstFailed, audit.EventOutcomeDenied, 2)
	seedLimiterRateAggregate(limiter, "b-failed", secondFailed, audit.EventOutcomeSuccess, 4)
	seedLimiterRateAggregate(limiter, "c-healthy", healthy, audit.EventOutcomeFailure, 3)
	firstFailed.setRecordError(goerrors.New("first journal failed"))
	secondFailed.setRecordError(goerrors.New("second journal failed"))

	err := limiter.Flush(context.Background())
	require.ErrorContains(t, err, "a-failed")
	require.ErrorContains(t, err, "first journal failed")
	require.ErrorContains(t, err, "b-failed")
	require.ErrorContains(t, err, "second journal failed")
	healthySummaries := auditEventsNamed(healthy.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, healthySummaries, 1)
	require.Equal(t, uint64(3), *healthySummaries[0].Count)

	firstFailed.setRecordError(nil)
	secondFailed.setRecordError(nil)
	require.NoError(t, limiter.Flush(context.Background()))
	firstSummaries := auditEventsNamed(firstFailed.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, firstSummaries, 1)
	require.Equal(t, uint64(2), *firstSummaries[0].Count)
	secondSummaries := auditEventsNamed(secondFailed.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, secondSummaries, 1)
	require.Equal(t, uint64(4), *secondSummaries[0].Count)
	require.Len(t, auditEventsNamed(healthy.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed), 1)
}

func TestUnauthenticatedAuditLimiterFlushUsesEmergencyReserveWithoutDuplicates(t *testing.T) {
	limiter := newTestUnauthenticatedAuditLimiter(time.Unix(5_475, 0), 1, 1)
	recorder := newLimiterTestRecorder(false)
	seedLimiterReserveAggregate(limiter, "security", recorder, 4)

	recorder.setRecordError(goerrors.New("reserve unavailable"))
	require.ErrorContains(t, limiter.Flush(context.Background()), "reserve unavailable")
	require.Empty(t, recorder.eventsSnapshot())
	recorder.setRecordError(nil)
	require.NoError(t, limiter.Flush(context.Background()))
	require.NoError(t, limiter.Flush(context.Background()))
	summaries := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluationsSuppressed)
	require.Len(t, summaries, 1)
	require.Equal(t, audit.EventReasonJournalReserve, summaries[0].Reason)
	require.Equal(t, uint64(4), *summaries[0].Count)
}

func TestExhaustedUnauthenticatedAuditLimitDoesNotBlockRequiredAudit(t *testing.T) {
	now := time.Unix(5_500, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	recorder := newLimiterTestRecorder(true)
	flow := configuration.FlowName("main")
	svc := &service{
		Service:              &Service{},
		unauthenticatedAudit: limiter,
		flowAuditRecorders:   map[configuration.FlowName]audit.Recorder{flow: recorder},
		flowAuditlogs:        map[configuration.FlowName]configuration.AuditlogName{flow: "security"},
		enabledAuditlogs:     map[configuration.AuditlogName]bool{"security": true},
	}
	ctx := limiterTestContext("192.0.2.55")
	denied := authorization.FlowAuthorizationObservation{Flow: flow, Method: authorization.FlowAuthorizationMethodPassword, Outcome: authorization.FlowAuthorizationOutcomeDenied}
	require.NoError(t, svc.observeFlowAuthorization(ctx, denied))
	require.NoError(t, svc.observeFlowAuthorization(ctx, denied))
	accepted := authorization.FlowAuthorizationObservation{Flow: flow, Method: authorization.FlowAuthorizationMethodPassword, Outcome: authorization.FlowAuthorizationOutcomeAccepted}
	require.NoError(t, svc.observeFlowAuthorization(ctx, accepted))

	events := recorder.eventsSnapshot()
	require.Equal(t, audit.EventOutcomeSuccess, events[len(events)-1].Outcome)
	require.Equal(t, audit.EventNameAuthenticationFlowEvaluated, events[len(events)-1].Name)
}

func TestUnauthenticatedAuditRecorderFailureClosesOnlyCurrentConnection(t *testing.T) {
	flow := configuration.FlowName("main")
	recorder := failingLimiterTestRecorder{}
	svc := &service{
		Service:              &Service{},
		unauthenticatedAudit: newTestUnauthenticatedAuditLimiter(time.Unix(5_750, 0), 1, 1),
		flowAuditRecorders:   map[configuration.FlowName]audit.Recorder{flow: recorder},
		flowAuditlogs:        map[configuration.FlowName]configuration.AuditlogName{flow: "security"},
		enabledAuditlogs:     map[configuration.AuditlogName]bool{"security": true},
	}
	firstServer, firstClient := net.Pipe()
	secondServer, secondClient := net.Pipe()
	defer firstClient.Close()
	defer secondClient.Close()
	firstContext := newLimiterSSHContext("192.0.2.71")
	secondContext := newLimiterSSHContext("192.0.2.72")
	first := &connection{Conn: firstServer, context: firstContext, service: svc}
	second := &connection{Conn: secondServer, context: secondContext, service: svc}
	firstContext.SetValue(connectionCtxKey, first)
	secondContext.SetValue(connectionCtxKey, second)
	svc.activeConnections.Store(2)

	err := svc.recordUnauthenticatedFlowAudit(firstContext, flow, audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied})
	require.Error(t, err)
	require.True(t, first.closed.Load())
	require.False(t, second.closed.Load())
	require.Equal(t, int64(1), svc.activeConnections.Load())
	require.NoError(t, second.Close())
}

func TestFlowAuthorizationObservationAuthenticationBoundary(t *testing.T) {
	tests := []struct {
		name         string
		observation  authorization.FlowAuthorizationObservation
		suppressible bool
	}{
		{"public-key candidate accepted", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPublicKey, Phase: authorization.FlowAuthorizationPhaseCandidate, Outcome: authorization.FlowAuthorizationOutcomeAccepted}, true},
		{"public-key candidate denied", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPublicKey, Phase: authorization.FlowAuthorizationPhaseCandidate, Outcome: authorization.FlowAuthorizationOutcomeDenied}, true},
		{"public-key verified denied", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPublicKey, Phase: authorization.FlowAuthorizationPhaseVerified, Outcome: authorization.FlowAuthorizationOutcomeDenied}, false},
		{"public-key verified accepted", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPublicKey, Phase: authorization.FlowAuthorizationPhaseVerified, Outcome: authorization.FlowAuthorizationOutcomeAccepted}, false},
		{"password denied", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPassword, Outcome: authorization.FlowAuthorizationOutcomeDenied}, true},
		{"password accepted", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodPassword, Outcome: authorization.FlowAuthorizationOutcomeAccepted}, false},
		{"interactive failed", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodKeyboardInteractive, Outcome: authorization.FlowAuthorizationOutcomeFailed}, true},
		{"interactive accepted", authorization.FlowAuthorizationObservation{Method: authorization.FlowAuthorizationMethodKeyboardInteractive, Outcome: authorization.FlowAuthorizationOutcomeAccepted}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.suppressible, flowAuthorizationObservationIsUnauthenticated(test.observation))
		})
	}
}

func TestCloseAuditFlushesAggregatesBeforeSealing(t *testing.T) {
	now := time.Unix(6_000, 0)
	limiter := newTestUnauthenticatedAuditLimiter(now, 1, 1)
	recorder := newLimiterTestRecorder(true)
	event := audit.Event{Name: audit.EventNameAuthenticationFlowEvaluated, Outcome: audit.EventOutcomeDenied}
	ctx := limiterTestContext("192.0.2.42")
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))
	require.NoError(t, limiter.Record(ctx, "security", true, recorder, event))

	svc := &service{
		Service:              &Service{},
		unauthenticatedAudit: limiter,
		auditRecorderOrder:   []audit.Recorder{recorder},
		auditRecorders:       map[configuration.AuditlogName]audit.Recorder{"security": recorder},
		auditDeliveries:      map[configuration.AuditlogName]*audit.RemoteDelivery{},
		flowAuditRecorders:   map[configuration.FlowName]audit.Recorder{},
		flowAuditlogs:        map[configuration.FlowName]configuration.AuditlogName{},
		enabledAuditlogs:     map[configuration.AuditlogName]bool{},
	}
	require.NoError(t, svc.closeAudit(true))
	operations := recorder.operationsSnapshot()
	require.Equal(t, []string{"suppressible", "suppressible", "record", "seal", "close"}, operations)
	require.Equal(t, uint64(1), *recorder.eventsSnapshot()[2].Count)
}

func TestCloseAuditReportsIncompleteAggregateFlushAndStillCloses(t *testing.T) {
	limiter := newTestUnauthenticatedAuditLimiter(time.Unix(6_250, 0), 1, 1)
	recorder := newLimiterTestRecorder(false)
	seedLimiterReserveAggregate(limiter, "security", recorder, 2)
	recorder.setRecordError(goerrors.New("disk unavailable"))
	svc := &service{
		Service:              &Service{},
		unauthenticatedAudit: limiter,
		auditRecorderOrder:   []audit.Recorder{recorder},
		auditRecorders:       map[configuration.AuditlogName]audit.Recorder{"security": recorder},
		auditDeliveries:      map[configuration.AuditlogName]*audit.RemoteDelivery{},
		flowAuditRecorders:   map[configuration.FlowName]audit.Recorder{},
		flowAuditlogs:        map[configuration.FlowName]configuration.AuditlogName{},
		enabledAuditlogs:     map[configuration.AuditlogName]bool{},
	}

	err := svc.closeAudit(true)
	require.ErrorContains(t, err, "cannot flush unauthenticated audit aggregates")
	require.ErrorContains(t, err, "disk unavailable")
	require.Equal(t, []string{"record", "seal", "close"}, recorder.operationsSnapshot())
}

func newTestUnauthenticatedAuditLimiter(now time.Time, perSource, global uint16) *unauthenticatedAuditLimiter {
	limiter := newUnauthenticatedAuditLimiter(configuration.SshUnauthenticatedAudit{
		Interval: common.DurationOf(time.Minute), PerSourceLimit: perSource, GlobalLimit: global,
	})
	limiter.now = func() time.Time { return now }
	limiter.global = newAuditTokenBucket(float64(global), now)
	return limiter
}

func seedLimiterRateAggregate(limiter *unauthenticatedAuditLimiter, name configuration.AuditlogName, recorder audit.Recorder, outcome audit.EventOutcome, count uint64) {
	state := limiter.auditlog(name, recorder)
	state.mutex.Lock()
	defer state.mutex.Unlock()
	at := limiter.now()
	state.rate[outcome] = &unauthenticatedAuditAggregate{pending: count, first: at, last: at, announced: true}
}

func seedLimiterReserveAggregate(limiter *unauthenticatedAuditLimiter, name configuration.AuditlogName, recorder audit.Recorder, count uint64) {
	state := limiter.auditlog(name, recorder)
	state.mutex.Lock()
	defer state.mutex.Unlock()
	at := limiter.now()
	state.reserve = unauthenticatedAuditReserve{phase: reservePhaseMonitoring, pending: count, first: at, last: at}
}

type limiterRemoteContext struct {
	context.Context
	remote net.Addr
}

type limiterSSHContext struct {
	context.Context
	sync.Mutex
	values sync.Map
	remote net.Addr
}

func newLimiterSSHContext(address string) *limiterSSHContext {
	return &limiterSSHContext{Context: context.Background(), remote: &net.TCPAddr{IP: net.ParseIP(address), Port: 22}}
}

func (this *limiterSSHContext) User() string                   { return "" }
func (this *limiterSSHContext) SessionID() string              { return "" }
func (this *limiterSSHContext) ClientVersion() string          { return "" }
func (this *limiterSSHContext) ServerVersion() string          { return "" }
func (this *limiterSSHContext) RemoteAddr() net.Addr           { return this.remote }
func (this *limiterSSHContext) LocalAddr() net.Addr            { return nil }
func (this *limiterSSHContext) Permissions() *essh.Permissions { return nil }

func (this *limiterSSHContext) Value(key any) any {
	if value, ok := this.values.Load(key); ok {
		return value
	}
	return this.Context.Value(key)
}

func (this *limiterSSHContext) SetValue(key, value any) {
	this.values.Store(key, value)
}

func (this limiterRemoteContext) RemoteAddr() net.Addr { return this.remote }

func limiterTestContext(address string) context.Context {
	return limiterRemoteContext{Context: context.Background(), remote: &net.TCPAddr{IP: net.ParseIP(address), Port: 22}}
}

type limiterTestRecorder struct {
	mutex             sync.Mutex
	events            []audit.Event
	operations        []string
	allowSuppressible bool
	recordErr         error
}

type blockingLimiterTestRecorder struct {
	delegate *limiterTestRecorder
	started  chan struct{}
	release  chan struct{}
	once     sync.Once
}

type failingLimiterTestRecorder struct{}

func (failingLimiterTestRecorder) Record(context.Context, audit.Event) error {
	return goerrors.New("record failed")
}

func (failingLimiterTestRecorder) Close() error { return nil }

func newLimiterTestRecorder(allowSuppressible bool) *limiterTestRecorder {
	return &limiterTestRecorder{allowSuppressible: allowSuppressible}
}

func newBlockingLimiterTestRecorder() *blockingLimiterTestRecorder {
	return &blockingLimiterTestRecorder{
		delegate: newLimiterTestRecorder(true),
		started:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
}

func (this *limiterTestRecorder) Record(_ context.Context, event audit.Event) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.operations = append(this.operations, "record")
	if this.recordErr != nil {
		return this.recordErr
	}
	this.events = append(this.events, event)
	return nil
}

func (this *limiterTestRecorder) RecordSuppressible(_ context.Context, event audit.Event) (bool, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.allowSuppressible {
		return false, nil
	}
	this.events = append(this.events, event)
	this.operations = append(this.operations, "suppressible")
	return true, nil
}

func (this *limiterTestRecorder) Seal() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.operations = append(this.operations, "seal")
	return nil
}

func (this *limiterTestRecorder) Close() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.operations = append(this.operations, "close")
	return nil
}

func (this *limiterTestRecorder) setSuppressible(value bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.allowSuppressible = value
}

func (this *limiterTestRecorder) setRecordError(err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.recordErr = err
}

func (this *limiterTestRecorder) eventsSnapshot() []audit.Event {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]audit.Event(nil), this.events...)
}

func (this *limiterTestRecorder) operationsSnapshot() []string {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]string(nil), this.operations...)
}

func (this *blockingLimiterTestRecorder) Record(ctx context.Context, event audit.Event) error {
	return this.delegate.Record(ctx, event)
}

func (this *blockingLimiterTestRecorder) RecordSuppressible(ctx context.Context, event audit.Event) (bool, error) {
	select {
	case this.started <- struct{}{}:
	case <-ctx.Done():
		return false, context.Cause(ctx)
	}
	select {
	case <-this.release:
	case <-ctx.Done():
		return false, context.Cause(ctx)
	}
	return this.delegate.RecordSuppressible(ctx, event)
}

func (this *blockingLimiterTestRecorder) Close() error {
	return this.delegate.Close()
}

func (this *blockingLimiterTestRecorder) unblock() {
	this.once.Do(func() { close(this.release) })
}

var _ audit.SuppressibleRecorder = (*limiterTestRecorder)(nil)
var _ audit.SealableRecorder = (*limiterTestRecorder)(nil)
var _ audit.SuppressibleRecorder = (*blockingLimiterTestRecorder)(nil)
