package audit

import (
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// DeliverySnapshot is a constant-space worker observation, not a repository
// inventory. PendingSince starts when an outstanding operation is first seen;
// it does not claim to be the oldest artifact's creation timestamp.
type DeliverySnapshot struct {
	Target       configuration.AuditlogTargetName
	Errors       uint64
	PendingSince time.Time
}

type deliveryMonitoring struct {
	mutex        sync.Mutex
	errors       uint64
	pendingSince time.Time
}

func (this *deliveryMonitoring) pending() {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.pendingSince.IsZero() {
		this.pendingSince = time.Now()
	}
}
func (this *deliveryMonitoring) failed() {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.errors++
	if this.pendingSince.IsZero() {
		this.pendingSince = time.Now()
	}
}
func (this *deliveryMonitoring) resolved() {
	this.mutex.Lock()
	this.pendingSince = time.Time{}
	this.mutex.Unlock()
}
func (this *deliveryMonitoring) snapshot(target configuration.AuditlogTargetName) DeliverySnapshot {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return DeliverySnapshot{Target: target, Errors: this.errors, PendingSince: this.pendingSince}
}

// MonitoringSnapshots reads memory only and never waits for target I/O.
func (this *RemoteDelivery) MonitoringSnapshots() []DeliverySnapshot {
	result := make([]DeliverySnapshot, 0, len(this.workers))
	for _, worker := range this.workers {
		result = append(result, worker.monitoring.snapshot(worker.scope.Target))
	}
	return result
}

func (this *RemoteArtifactDelivery) MonitoringSnapshots() []DeliverySnapshot {
	result := make([]DeliverySnapshot, 0, len(this.workers))
	for _, worker := range this.workers {
		result = append(result, worker.monitoring.snapshot(worker.entry.scope.Target))
	}
	return result
}
