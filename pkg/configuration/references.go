package configuration

import "github.com/engity-com/bifroest/pkg/errors"

// Resolve afresh in the complete root context, including on programmatic
// Validate calls. Keep the declaration separate from each effective runtime V.
func (this *Configuration) resolveFlowReferences() error {
	flows := append(Flows(nil), this.Flows...)
	for index := range flows {
		flow := &flows[index]
		environment := &flow.Environment
		if environment.V == nil && !environment.Variables.IsZero() {
			return errors.Config.Newf("[flows][%d][environment] required but absent", index)
		}
		if environment.Reference != "" && environment.V != nil && !environment.resolved {
			return errors.Config.Newf("[flows][%d][environment] cannot combine a reference and an inline value", index)
		}
		if environment.Reference != "" || environment.V == nil || environment.resolved {
			name := environment.Reference
			if name == "" {
				name = "default"
			}
			definition, exists := this.Environments[name]
			if !exists {
				if environment.Reference != "" {
					return errors.Config.Newf("[flows][%d][environment] references unknown environment %q", index, name)
				}
				return errors.Config.Newf("[flows][%d][environment] required but absent", index)
			}
			reference := environment.Reference
			*environment = cloneConfigurationValue(definition)
			environment.Reference, environment.resolved = reference, true
		}
		authorization := &flow.Authorization
		if authorization.V == nil && !authorization.Principal.IsZero() {
			return errors.Config.Newf("[flows][%d][authorization] required but absent", index)
		}
		if authorization.Reference != "" && authorization.V != nil && !authorization.resolved {
			return errors.Config.Newf("[flows][%d][authorization] cannot combine a reference and an inline value", index)
		}
		if authorization.Reference != "" || authorization.V == nil || authorization.resolved {
			name := authorization.Reference
			if name == "" {
				name = "default"
			}
			definition, exists := this.Authorizations[name]
			if !exists {
				if authorization.Reference != "" {
					return errors.Config.Newf("[flows][%d][authorization] references unknown authorization %q", index, name)
				}
				return errors.Config.Newf("[flows][%d][authorization] required but absent", index)
			}
			reference := authorization.Reference
			*authorization = cloneConfigurationValue(definition)
			authorization.Reference, authorization.resolved = reference, true
		}
		if flow.Auditlog == "" || (flow.auditlogResolved && flow.Auditlog == flow.resolvedAuditlog) {
			flow.Auditlog = ""
			for _, auditlog := range this.Auditlogs {
				if auditlog.Name == DefaultAuditlogName {
					flow.Auditlog = DefaultAuditlogName
					break
				}
			}
			flow.auditlogResolved, flow.resolvedAuditlog = true, flow.Auditlog
		} else {
			flow.auditlogResolved = false
		}
	}
	candidate := *this
	candidate.Flows = flows
	if err := candidate.validateAuditlogReferences(); err != nil {
		return err
	}
	copy(this.Flows, flows)
	return nil
}
