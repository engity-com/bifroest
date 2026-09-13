package service

import (
	"container/list"
	"context"
	goerrors "errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

const maxUnauthenticatedAuditSources = 4096

type unauthenticatedAuditLimiter struct {
	globalMutex sync.Mutex
	interval    time.Duration
	perSource   float64
	global      auditTokenBucket
	now         func() time.Time
	sources     map[string]*unauthenticatedAuditSource
	sourceOrder list.List
	auditlogs   map[configuration.AuditlogName]*unauthenticatedAuditLog
}

type auditTokenBucket struct {
	capacity float64
	tokens   float64
	last     time.Time
}

func newAuditTokenBucket(capacity float64, now time.Time) auditTokenBucket {
	return auditTokenBucket{capacity: capacity, tokens: capacity, last: now}
}

func (this *auditTokenBucket) refill(now time.Time, interval time.Duration) {
	if !now.After(this.last) {
		return
	}
	this.tokens += now.Sub(this.last).Seconds() / interval.Seconds() * this.capacity
	if this.tokens > this.capacity {
		this.tokens = this.capacity
	}
	this.last = now
}

type unauthenticatedAuditSource struct {
	key     string
	bucket  auditTokenBucket
	element *list.Element
}

type unauthenticatedAuditAggregate struct {
	pending        uint64
	first          time.Time
	last           time.Time
	lastSuppressed time.Time
	lastFlush      time.Time
	announced      bool
}

type reservePhase uint8

const (
	reservePhaseInactive reservePhase = iota
	reservePhaseMarkerPending
	reservePhaseMonitoring
)

type unauthenticatedAuditReserve struct {
	phase     reservePhase
	pending   uint64
	first     time.Time
	last      time.Time
	nextCheck time.Time
}

func (this *unauthenticatedAuditReserve) active() bool {
	return this.phase != reservePhaseInactive
}

func (this *unauthenticatedAuditReserve) awaitMarker(nextCheck time.Time) {
	this.phase = reservePhaseMarkerPending
	this.nextCheck = nextCheck
}

func (this *unauthenticatedAuditReserve) monitor(nextCheck time.Time) {
	this.phase = reservePhaseMonitoring
	this.nextCheck = nextCheck
}

func (this *unauthenticatedAuditReserve) deactivate() {
	this.phase = reservePhaseInactive
	this.nextCheck = time.Time{}
}

type unauthenticatedAuditLog struct {
	mutex    sync.Mutex
	name     configuration.AuditlogName
	recorder audit.Recorder
	rate     map[audit.EventOutcome]*unauthenticatedAuditAggregate
	reserve  unauthenticatedAuditReserve
}

func newUnauthenticatedAuditLimiter(conf configuration.SshUnauthenticatedAudit) *unauthenticatedAuditLimiter {
	now := time.Now()
	return &unauthenticatedAuditLimiter{
		interval:  conf.Interval.Native(),
		perSource: float64(conf.PerSourceLimit),
		global:    newAuditTokenBucket(float64(conf.GlobalLimit), now),
		now:       time.Now,
		sources:   make(map[string]*unauthenticatedAuditSource, maxUnauthenticatedAuditSources),
		auditlogs: make(map[configuration.AuditlogName]*unauthenticatedAuditLog),
	}
}

func (this *unauthenticatedAuditLimiter) Record(ctx context.Context, auditlog configuration.AuditlogName, enabled bool, recorder audit.Recorder, event audit.Event) error {
	if this == nil || !enabled {
		return recorder.Record(ctx, event)
	}
	state := this.auditlog(auditlog, recorder)
	state.mutex.Lock()
	defer state.mutex.Unlock()
	now := this.now()

	if state.reserve.active() {
		handled, err := this.handleReserved(ctx, state, now)
		if err != nil || handled {
			return err
		}
	}
	if this.allow(unauthenticatedAuditSourceKey(ctx), now) {
		recorded, err := recordSuppressible(ctx, recorder, event)
		if err != nil || recorded {
			return err
		}
		return this.enterReserve(ctx, state, 1, now)
	}
	return this.suppressRate(ctx, state, event.Outcome, now)
}

func (this *unauthenticatedAuditLimiter) auditlog(name configuration.AuditlogName, recorder audit.Recorder) *unauthenticatedAuditLog {
	this.globalMutex.Lock()
	defer this.globalMutex.Unlock()
	state := this.auditlogs[name]
	if state == nil {
		state = &unauthenticatedAuditLog{
			name:     name,
			recorder: recorder,
			rate:     make(map[audit.EventOutcome]*unauthenticatedAuditAggregate),
		}
		this.auditlogs[name] = state
	}
	return state
}

func (this *unauthenticatedAuditLimiter) allow(source string, now time.Time) bool {
	this.globalMutex.Lock()
	defer this.globalMutex.Unlock()
	this.global.refill(now, this.interval)
	if this.global.tokens < 1 {
		return false
	}
	entry := this.sources[source]
	if entry == nil {
		if len(this.sources) == maxUnauthenticatedAuditSources {
			oldest := this.sourceOrder.Back()
			entry = oldest.Value.(*unauthenticatedAuditSource)
			delete(this.sources, entry.key)
			this.sourceOrder.Remove(oldest)
		}
		entry = &unauthenticatedAuditSource{key: source, bucket: newAuditTokenBucket(this.perSource, now)}
		entry.element = this.sourceOrder.PushFront(entry)
		this.sources[source] = entry
	} else {
		this.sourceOrder.MoveToFront(entry.element)
		entry.bucket.refill(now, this.interval)
	}
	if entry.bucket.tokens < 1 {
		return false
	}
	this.global.tokens--
	entry.bucket.tokens--
	return true
}

func (this *unauthenticatedAuditLimiter) suppressRate(ctx context.Context, auditlog *unauthenticatedAuditLog, outcome audit.EventOutcome, now time.Time) error {
	state := auditlog.rate[outcome]
	if state == nil {
		state = &unauthenticatedAuditAggregate{}
		auditlog.rate[outcome] = state
	}
	if state.announced && now.Sub(state.lastSuppressed) >= this.interval {
		enteredReserve, err := this.flushRate(ctx, auditlog, outcome, state, now)
		if err != nil {
			return err
		}
		if enteredReserve {
			addUnauthenticatedAuditCount(&state.pending, &state.first, &state.last, 1, now)
			state.lastSuppressed = now
			return nil
		}
		state.announced = false
	}
	if !state.announced {
		_, err := this.recordRateSummary(ctx, auditlog, unauthenticatedAuditSummary(outcome, audit.EventReasonRateLimit, 1, now, now), now)
		if err != nil {
			return err
		}
		state.announced = true
		state.lastSuppressed = now
		state.lastFlush = now
		return nil
	}
	if state.pending > 0 && now.Sub(state.lastFlush) >= this.interval {
		enteredReserve, err := this.flushRate(ctx, auditlog, outcome, state, now)
		if err != nil {
			return err
		}
		if enteredReserve {
			addUnauthenticatedAuditCount(&state.pending, &state.first, &state.last, 1, now)
			state.lastSuppressed = now
			return nil
		}
		state.lastFlush = now
	}
	addUnauthenticatedAuditCount(&state.pending, &state.first, &state.last, 1, now)
	state.lastSuppressed = now
	return nil
}

func (this *unauthenticatedAuditLimiter) flushRate(ctx context.Context, auditlog *unauthenticatedAuditLog, outcome audit.EventOutcome, state *unauthenticatedAuditAggregate, now time.Time) (bool, error) {
	if state.pending == 0 {
		return false, nil
	}
	enteredReserve, err := this.recordRateSummary(ctx, auditlog, unauthenticatedAuditSummary(outcome, audit.EventReasonRateLimit, state.pending, state.first, state.last), now)
	if err != nil {
		return false, err
	}
	state.pending = 0
	state.first = time.Time{}
	state.last = time.Time{}
	return enteredReserve, nil
}

func (this *unauthenticatedAuditLimiter) recordRateSummary(ctx context.Context, state *unauthenticatedAuditLog, event audit.Event, now time.Time) (bool, error) {
	recorded, err := recordSuppressible(ctx, state.recorder, event)
	if err != nil || recorded {
		return false, err
	}
	// The rate-limit count already exists and must retain its reason and outcome.
	// Persist it once from the reserve before suppressing subsequent details.
	if err := state.recorder.Record(ctx, event); err != nil {
		return false, err
	}
	state.reserve.awaitMarker(now.Add(this.interval))
	return true, nil
}

func (this *unauthenticatedAuditLimiter) handleReserved(ctx context.Context, state *unauthenticatedAuditLog, now time.Time) (bool, error) {
	reserved := &state.reserve
	if reserved.phase == reservePhaseMarkerPending {
		if !now.Before(reserved.nextCheck) {
			reserved.deactivate()
			return false, nil
		}
		if err := state.recorder.Record(ctx, unauthenticatedAuditSummary("", audit.EventReasonJournalReserve, 1, now, now)); err != nil {
			return true, err
		}
		reserved.monitor(now.Add(this.interval))
		return true, nil
	}
	if now.Before(reserved.nextCheck) {
		addUnauthenticatedAuditCount(&reserved.pending, &reserved.first, &reserved.last, 1, now)
		return true, nil
	}
	if reserved.pending > 0 {
		recorded, err := recordSuppressible(ctx, state.recorder, unauthenticatedAuditSummary("", audit.EventReasonJournalReserve, reserved.pending, reserved.first, reserved.last))
		if err != nil {
			return true, err
		}
		if !recorded {
			reserved.nextCheck = now.Add(this.interval)
			addUnauthenticatedAuditCount(&reserved.pending, &reserved.first, &reserved.last, 1, now)
			return true, nil
		}
		clearUnauthenticatedAuditCount(&reserved.pending, &reserved.first, &reserved.last)
	}
	reserved.deactivate()
	return false, nil
}

func (this *unauthenticatedAuditLimiter) enterReserve(ctx context.Context, state *unauthenticatedAuditLog, count uint64, at time.Time) error {
	if state.reserve.active() {
		addUnauthenticatedAuditCount(&state.reserve.pending, &state.reserve.first, &state.reserve.last, count, at)
		return nil
	}
	if err := state.recorder.Record(ctx, unauthenticatedAuditSummary("", audit.EventReasonJournalReserve, count, at, at)); err != nil {
		return err
	}
	state.reserve.monitor(at.Add(this.interval))
	return nil
}

func (this *unauthenticatedAuditLimiter) Flush(ctx context.Context) error {
	if this == nil {
		return nil
	}
	this.globalMutex.Lock()
	auditlogs := make([]*unauthenticatedAuditLog, 0, len(this.auditlogs))
	for _, state := range this.auditlogs {
		auditlogs = append(auditlogs, state)
	}
	this.globalMutex.Unlock()

	sort.Slice(auditlogs, func(i, j int) bool { return auditlogs[i].name < auditlogs[j].name })
	var result error
	for _, state := range auditlogs {
		state.mutex.Lock()
		result = goerrors.Join(result, flushUnauthenticatedAuditLog(ctx, state))
		state.mutex.Unlock()
	}
	return result
}

func flushUnauthenticatedAuditLog(ctx context.Context, state *unauthenticatedAuditLog) error {
	outcomes := make([]audit.EventOutcome, 0, len(state.rate))
	for outcome := range state.rate {
		outcomes = append(outcomes, outcome)
	}
	sort.Slice(outcomes, func(i, j int) bool { return outcomes[i] < outcomes[j] })
	var result error
	for _, outcome := range outcomes {
		aggregate := state.rate[outcome]
		if aggregate.pending == 0 {
			continue
		}
		event := unauthenticatedAuditSummary(outcome, audit.EventReasonRateLimit, aggregate.pending, aggregate.first, aggregate.last)
		if err := state.recorder.Record(ctx, event); err != nil {
			result = goerrors.Join(result, fmt.Errorf("cannot flush rate-limit aggregate for auditlog %q: %w", state.name, err))
			continue
		}
		clearUnauthenticatedAuditCount(&aggregate.pending, &aggregate.first, &aggregate.last)
	}
	reserved := &state.reserve
	if reserved.active() && reserved.pending > 0 {
		event := unauthenticatedAuditSummary("", audit.EventReasonJournalReserve, reserved.pending, reserved.first, reserved.last)
		if err := state.recorder.Record(ctx, event); err != nil {
			result = goerrors.Join(result, fmt.Errorf("cannot flush journal-reserve aggregate for auditlog %q: %w", state.name, err))
		} else {
			clearUnauthenticatedAuditCount(&reserved.pending, &reserved.first, &reserved.last)
		}
	}
	return result
}

func recordSuppressible(ctx context.Context, recorder audit.Recorder, event audit.Event) (bool, error) {
	if suppressible, ok := recorder.(audit.SuppressibleRecorder); ok {
		return suppressible.RecordSuppressible(ctx, event)
	}
	if err := recorder.Record(ctx, event); err != nil {
		return false, err
	}
	return true, nil
}

func unauthenticatedAuditSummary(outcome audit.EventOutcome, reason audit.EventReason, count uint64, first, last time.Time) audit.Event {
	duration := last.Sub(first).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return audit.Event{
		Name:           audit.EventNameAuthenticationFlowEvaluationsSuppressed,
		Domain:         audit.EventDomainAuthentication,
		Outcome:        outcome,
		Reason:         reason,
		Count:          common.P(count),
		DurationMillis: common.P(duration),
	}
}

func addUnauthenticatedAuditCount(count *uint64, first, last *time.Time, amount uint64, at time.Time) {
	if *count == 0 {
		*first = at
	}
	if ^uint64(0)-*count < amount {
		*count = ^uint64(0)
	} else {
		*count += amount
	}
	*last = at
}

func clearUnauthenticatedAuditCount(count *uint64, first, last *time.Time) {
	*count = 0
	*first = time.Time{}
	*last = time.Time{}
}

func unauthenticatedAuditSourceKey(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	var address net.Addr
	if remote, ok := ctx.(interface{ RemoteAddr() net.Addr }); ok {
		address = remote.RemoteAddr()
	}
	if address == nil {
		if candidate, ok := ctx.Value(essh.ContextKeyRemoteAddr).(net.Addr); ok {
			address = candidate
		}
	}
	return normalizeUnauthenticatedAuditSource(address)
}

func normalizeUnauthenticatedAuditSource(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	var ip net.IP
	switch value := address.(type) {
	case *net.TCPAddr:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		host, _, err := net.SplitHostPort(address.String())
		if err == nil {
			parsed, parseErr := netip.ParseAddr(host)
			if parseErr == nil {
				return normalizedUnauthenticatedAuditAddress(parsed)
			}
		}
		return "unknown"
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "unknown"
	}
	return normalizedUnauthenticatedAuditAddress(parsed)
}

func normalizedUnauthenticatedAuditAddress(address netip.Addr) string {
	address = address.Unmap()
	if address.Is4() {
		return address.String()
	}
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return "unknown"
}
