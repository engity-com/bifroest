package configuration

import "slices"

// ReloadChanges describes configuration differences, not permission to apply
// them live. The runtime must reject every unsupported change before activation.
// Only names and field paths are included; provider values and secrets are not.
type ReloadChanges struct {
	// Changed includes declaration-only changes, such as switching between two
	// equivalent references. Filename is source metadata, not a setting.
	Changed bool

	AddedFlows    []FlowName
	RemovedFlows  []FlowName
	ModifiedFlows []FlowReloadChange

	// FlowOrderChanged detects a different relative order of retained flows.
	// Additions and removals are already represented separately.
	FlowOrderChanged bool

	// Sections contains changed process-wide settings in a stable order.
	Sections []string
}

type FlowReloadChange struct {
	Name          FlowName
	Authorization bool
	Environment   bool
	Auditlog      bool
	Policy        bool
}

// RuntimeChanged excludes unused root definitions and equivalent reference
// declarations. They still need to replace the accepted source snapshot.
func (this ReloadChanges) RuntimeChanged() bool {
	return len(this.AddedFlows) > 0 || len(this.RemovedFlows) > 0 ||
		len(this.ModifiedFlows) > 0 || this.FlowOrderChanged || len(this.Sections) > 0
}

// ChangesTo compares effective, resolved flow values. Declaration-oriented
// IsEqualTo methods deliberately also compare reference names, so they cannot
// alone decide whether a flow requires new runtime resources.
func (this *Snapshot) ChangesTo(next *Snapshot) ReloadChanges {
	before, after := &this.configuration, &next.configuration
	result := ReloadChanges{Changed: !before.IsEqualTo(after)}

	previousFlows := make(map[FlowName]Flow, len(before.Flows))
	nextFlows := make(map[FlowName]Flow, len(after.Flows))
	for _, flow := range before.Flows {
		previousFlows[flow.Name] = flow
	}
	for _, flow := range after.Flows {
		nextFlows[flow.Name] = flow
	}

	var previousOrder, nextOrder []FlowName
	for _, flow := range before.Flows {
		if _, exists := nextFlows[flow.Name]; exists {
			previousOrder = append(previousOrder, flow.Name)
		} else {
			result.RemovedFlows = append(result.RemovedFlows, flow.Name)
		}
	}
	for _, flow := range after.Flows {
		previous, exists := previousFlows[flow.Name]
		if !exists {
			result.AddedFlows = append(result.AddedFlows, flow.Name)
			continue
		}
		nextOrder = append(nextOrder, flow.Name)
		change := FlowReloadChange{
			Name:          flow.Name,
			Authorization: !effectiveAuthorizationEqual(previous.Authorization, flow.Authorization),
			Environment:   !effectiveEnvironmentEqual(previous.Environment, flow.Environment),
			Auditlog:      !effectiveAuditlogEqual(before, previous.Auditlog, after, flow.Auditlog),
			Policy:        !flowPolicyEqual(previous, flow),
		}
		if change.Authorization || change.Environment || change.Auditlog || change.Policy {
			result.ModifiedFlows = append(result.ModifiedFlows, change)
		}
	}
	result.FlowOrderChanged = !slices.Equal(previousOrder, nextOrder)

	for _, section := range []struct {
		name  string
		equal bool
	}{
		{"ssh", before.Ssh.IsEqualTo(after.Ssh)},
		{"http", before.Http.IsEqualTo(after.Http)},
		{"monitoring", before.Monitoring.IsEqualTo(after.Monitoring)},
		{"tls", before.Tls.IsEqualTo(after.Tls)},
		{"session", before.Session.IsEqualTo(after.Session)},
		{"housekeeping", before.HouseKeeping.IsEqualTo(after.HouseKeeping)},
		{"alternatives", before.Alternatives.IsEqualTo(after.Alternatives)},
		{"startMessage", before.StartMessage.IsEqualTo(after.StartMessage)},
		{"auditlogs", before.Auditlogs.IsEqualTo(after.Auditlogs)},
	} {
		if !section.equal {
			result.Sections = append(result.Sections, section.name)
		}
	}
	return result
}

func effectiveAuthorizationEqual(before, after Authorization) bool {
	before.Reference, after.Reference = "", ""
	before.resolved, after.resolved = false, false
	return before.IsEqualTo(after)
}

func effectiveEnvironmentEqual(before, after Environment) bool {
	before.Reference, after.Reference = "", ""
	before.resolved, after.resolved = false, false
	return before.IsEqualTo(after)
}

func flowPolicyEqual(before, after Flow) bool {
	before.Authorization, after.Authorization = Authorization{}, Authorization{}
	before.Environment, after.Environment = Environment{}, Environment{}
	before.Auditlog, after.Auditlog = "", ""
	before.auditlogResolved, after.auditlogResolved = false, false
	before.resolvedAuditlog, after.resolvedAuditlog = "", ""
	return before.IsEqualTo(after)
}

func effectiveAuditlogEqual(before *Configuration, previous AuditlogName, after *Configuration, next AuditlogName) bool {
	if previous != next {
		return false
	}
	if previous == "" {
		return true
	}
	// Snapshots are validated: nonempty references necessarily resolve.
	for _, left := range before.Auditlogs {
		if left.Name != previous {
			continue
		}
		for _, right := range after.Auditlogs {
			if right.Name == next {
				return left.IsEqualTo(right)
			}
		}
	}
	return false
}
