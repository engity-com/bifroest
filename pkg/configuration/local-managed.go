//go:build unix || windows

package configuration

// LocalManagedGroupFor returns the current flow's local-environment management
// selector. A missing flow, non-local environment or empty selector means that
// this capability is not available, not that an account is unmanaged. The first
// matching flow retains the service's existing selection semantics.
func (this Flows) LocalManagedGroupFor(name FlowName) (string, bool) {
	for _, flow := range this {
		if flow.Name != name {
			continue
		}
		local, ok := flow.Environment.V.(*EnvironmentLocal)
		if !ok || local == nil || local.ManagedGroup == "" {
			return "", false
		}
		return local.ManagedGroup, true
	}
	return "", false
}
