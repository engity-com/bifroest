package configuration

// EnvironmentCanReuse relaxes revision equality only for explicit provisioning
// choices. Backend credentials and all identity/target/policy selectors remain
// equal; resolved targets and stored environment credentials are checked again
// by the service/provider. Unknown provider types get no relaxed comparison.
func EnvironmentCanReuse(before, after Environment) bool {
	if before.V == nil || after.V == nil {
		return false
	}
	before, after = environmentWithoutPresentation(before), environmentWithoutPresentation(after)
	switch previous := before.V.(type) {
	case *EnvironmentDummy:
		_, ok := after.V.(*EnvironmentDummy)
		return ok
	case *EnvironmentDocker:
		current, ok := after.V.(*EnvironmentDocker)
		if !ok {
			return false
		}
		copyOfCurrent := *current
		copyOfCurrent.Image = previous.Image
		copyOfCurrent.ImagePullPolicy = previous.ImagePullPolicy
		copyOfCurrent.ImagePullCredentials = previous.ImagePullCredentials
		// Acceptance is always evaluated using the admitted generation.
		copyOfCurrent.LoginAllowed = previous.LoginAllowed
		after.V = &copyOfCurrent
	case *EnvironmentKubernetes:
		current, ok := after.V.(*EnvironmentKubernetes)
		if !ok {
			return false
		}
		copyOfCurrent := *current
		copyOfCurrent.Image = previous.Image
		copyOfCurrent.ImagePullPolicy = previous.ImagePullPolicy
		copyOfCurrent.ImagePullCredentials = previous.ImagePullCredentials
		copyOfCurrent.ImagePullSecretName = previous.ImagePullSecretName
		copyOfCurrent.LoginAllowed = previous.LoginAllowed
		after.V = &copyOfCurrent
	}
	return effectiveEnvironmentEqual(before, after)
}
