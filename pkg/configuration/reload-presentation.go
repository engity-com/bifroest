package configuration

import "github.com/engity-com/bifroest/pkg/template"

// AccessChangesTo excludes an explicit allowlist of presentation-only fields.
// Templates in identity, target, credential or policy fields are never ignored.
// ChangesTo still includes these fields so accepted generations get new text.
func (this *Snapshot) AccessChangesTo(next *Snapshot) ReloadChanges {
	before, after := *this, *next
	before.configuration, after.configuration = this.Configuration(), next.Configuration()
	for index, flow := range before.configuration.Flows {
		before.configuration.Flows[index] = flowWithoutPresentation(flow)
	}
	for index, flow := range after.configuration.Flows {
		after.configuration.Flows[index] = flowWithoutPresentation(flow)
	}
	return before.ChangesTo(&after)
}

func flowWithoutPresentation(flow Flow) Flow {
	flow.Title = ""
	switch value := flow.Authorization.V.(type) {
	case *AuthorizationOidcDeviceAuth:
		copyOfValue := *value
		copyOfValue.Ssh = AuthorizationOidcSsh{}
		flow.Authorization.V = &copyOfValue
	case *AuthorizationOidcAuthorizationCode:
		copyOfValue := *value
		copyOfValue.Ssh = AuthorizationOidcSsh{}
		flow.Authorization.V = &copyOfValue
	}
	flow.Environment = environmentWithoutPresentation(flow.Environment)
	return flow
}

func environmentWithoutPresentation(env Environment) Environment {
	switch value := env.V.(type) {
	case *EnvironmentDummy:
		copyOfValue := *value
		copyOfValue.Banner = template.String{}
		env.V = &copyOfValue
	case *EnvironmentLocal:
		copyOfValue := *value
		copyOfValue.Banner = template.String{}
		env.V = &copyOfValue
	case *EnvironmentSsh:
		copyOfValue := *value
		copyOfValue.Banner = template.String{}
		env.V = &copyOfValue
	case *EnvironmentDocker:
		copyOfValue := *value
		copyOfValue.Banner = template.String{}
		env.V = &copyOfValue
	case *EnvironmentKubernetes:
		copyOfValue := *value
		copyOfValue.Banner = template.String{}
		env.V = &copyOfValue
	}
	return env
}
