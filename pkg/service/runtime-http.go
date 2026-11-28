package service

import (
	"context"
	"net/http"
	"sync"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// The response/stream handler pins every provider whose authorization it uses,
// including grants minted by an older, otherwise unchanged generation.
type webRequestLifetime struct {
	mutex    sync.Mutex
	closed   bool
	releases []func()
}

func (this *webRequestLifetime) add(release func()) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		release()
		return false
	}
	this.releases = append(this.releases, release)
	return true
}

func (this *webRequestLifetime) close() {
	this.mutex.Lock()
	this.closed = true
	releases := this.releases
	this.releases = nil
	this.mutex.Unlock()
	for _, release := range releases {
		release()
	}
}

func (this *webService) forService(svc *service) *webService {
	return &webService{service: svc, ctx: this.ctx, webState: this.webState}
}

func (this *webService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	owner := this.service
	if owner.resources != nil {
		selection, release, err := owner.runtime.selectCurrent()
		if err != nil {
			webError(w, http.StatusServiceUnavailable, "web service unavailable")
			return
		}
		defer release()
		owner, err = owner.resources.generationService(selection.generation)
		if err != nil {
			webError(w, http.StatusServiceUnavailable, "web service unavailable")
			return
		}
	}
	if observation, _ := r.Context().Value(monitoringRequestKey{}).(*monitoringRequest); observation != nil && owner.monitoring != nil {
		observation.view.Store(owner.monitoring)
	}
	view := this.forService(owner)
	view.request = &webRequestLifetime{}
	defer view.request.close()
	view.serveHTTP(w, r)
}

func (this *runtimeGenerations) webFlowCurrentLocked(generation *runtimeGeneration, flow configuration.FlowName, revision *runtimeFlowRevision) bool {
	if this.stopped || this.current.httpDisabled || !this.liveLocked(generation) || revision == nil {
		return false
	}
	before, exists := generation.flows[flow]
	current, present := this.current.flows[flow]
	return exists && present && !before.identity.revoked && before.identity == current.identity && before.actions == revision && current.actions == revision
}

func (this *runtimeGenerations) webFlowCurrent(generation *runtimeGeneration, flow configuration.FlowName, revision *runtimeFlowRevision) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.webFlowCurrentLocked(generation, flow, revision)
}

func (this *runtimeGenerations) admitWeb(generation *runtimeGeneration, revision *runtimeFlowRevision, conn *terminalConnection) (func(), error) {
	flow := conn.session.Flow()
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.webFlowCurrentLocked(generation, flow, revision) {
		return nil, errWebAccessDenied
	}
	return this.admitLocked(generation, conn)
}

func (this *webService) flowRevision(flow configuration.FlowName) *runtimeFlowRevision {
	if this.service.generation == nil {
		return nil
	}
	return this.service.generation.flows[flow].actions
}

func (this *webService) flowCurrent(flow configuration.FlowName, revision *runtimeFlowRevision) bool {
	return this.service.runtime == nil || this.service.runtime.webFlowCurrent(this.service.generation, flow, revision)
}

// Publication is serialized with activation, but never holds the registry mutex
// while touching browser state. Call only after all slow/fallible preparation.
func (this *webService) lockPublication(flow configuration.FlowName, revision *runtimeFlowRevision) (func(), error) {
	if this.service.runtime == nil {
		return func() {}, nil
	}
	registry := this.service.runtime
	registry.webPublication.RLock()
	if !registry.webFlowCurrent(this.service.generation, flow, revision) {
		registry.webPublication.RUnlock()
		return nil, errWebAccessDenied
	}
	return registry.webPublication.RUnlock, nil
}

func (this *webService) useAccess(access *webAccess) error {
	if !this.flowCurrent(access.auth.Flow(), access.revision) {
		return errWebAccessDenied
	}
	if this.request == nil || access.owner == nil {
		return nil // Lean adapters/tests may have no generation registry.
	}
	release, err := access.owner.retainRuntime()
	if err != nil {
		return err
	}
	if !this.request.add(release) {
		return context.Canceled
	}
	return nil
}
