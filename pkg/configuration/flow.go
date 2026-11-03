package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
)

// Flow represents a dedicated flow within the service.
//
// Each flow has a unique Name where it can be identified with.
//
// # Steps
//
// It follows the follows steps:
//  1. Check if the current connection meet the defined Requirement.
//  2. Register a new session or use an existing one based on Session configuration
//     (configured via root Configuration - because is used by every flow together).
//  3. Try to authorize the current connection based on Authorization.
//  4. If it was successfully authorized create and run a new Environment.
type Flow struct {
	// Name unique name within the while configuration which identifies the Flow.
	Name FlowName `yaml:"name"`

	// Auditlog references the audit log used by this flow.
	Auditlog         AuditlogName `yaml:"auditlog,omitempty"`
	auditlogResolved bool
	resolvedAuditlog AuditlogName

	Ssh            FlowSsh  `yaml:"ssh,omitempty"`
	Http           FlowHttp `yaml:"http,omitempty"`
	DiscoverAsSlug string   `yaml:"discoverAsSlug,omitempty"`

	// Requirement represents all rules the connection has to meet to be able to be accepted by this flow.
	Requirement Requirement `yaml:"requirement,omitempty"`

	// Authorization defines how a connection can be authorized to get access to this flow.
	Authorization Authorization `yaml:"authorization"`

	// Environment defines to which Environment the connection will be connected ones every step before was successful.
	Environment Environment `yaml:"environment"`
}

func (this *Flow) SetDefaults() error {
	this.auditlogResolved, this.resolvedAuditlog = false, ""
	return setDefaults(this,
		noopSetDefault[Flow]("name"),
		fixedDefault("auditlog", func(v *Flow) *AuditlogName { return &v.Auditlog }, ""),
		func(v *Flow) (string, defaulter) { return "ssh", &v.Ssh },
		func(v *Flow) (string, defaulter) { return "http", &v.Http },
		noopSetDefault[Flow]("discoverAsSlug"),

		func(v *Flow) (string, defaulter) { return "requirement", &v.Requirement },
		func(v *Flow) (string, defaulter) { return "authorization", &v.Authorization },
		func(v *Flow) (string, defaulter) { return "environment", &v.Environment },
	)
}

func (this *Flow) Trim() error {
	return this.trim(true)
}

func (this *Flow) trim(requireResolved bool) error {
	return trim(&flowValidation{this, requireResolved},
		func(v *flowValidation) (string, trimmer) { return "ssh", &v.Ssh },
		func(v *flowValidation) (string, trimmer) { return "http", &v.Http },

		func(v *flowValidation) (string, trimmer) { return "requirement", &v.Requirement },
		func(v *flowValidation) (string, trimmer) {
			if !requireResolved && v.Authorization.V == nil {
				return "authorization", &noopT{}
			}
			return "authorization", &v.Authorization
		},
		func(v *flowValidation) (string, trimmer) {
			if !requireResolved && v.Environment.V == nil {
				return "environment", &noopT{}
			}
			return "environment", &v.Environment
		},
	)
}

type flowValidation struct {
	*Flow
	requireResolved bool
}

func (this *flowValidation) Validate() error { return this.Flow.validate(this.requireResolved) }

func (this *Flow) Validate() error {
	return this.validate(true)
}

func (this *Flow) validate(requireResolved bool) error {
	if err := validate(this,
		notZeroValidate("name", func(v *Flow) *FlowName { return &v.Name }),
		func(v *Flow) (string, validator) {
			if v.Auditlog == "" {
				return "auditlog", &noopT{}
			}
			return "auditlog", &v.Auditlog
		},
		func(v *Flow) (string, validator) { return "ssh", &v.Ssh },
		func(v *Flow) (string, validator) { return "http", &v.Http },
		func(v *Flow) (string, validator) {
			return "discoverAsSlug", validatorFunc(func() error { return net.ValidateHttpSlug(v.DiscoverAsSlug) })
		},

		func(v *Flow) (string, validator) { return "requirement", &v.Requirement },
		func(v *Flow) (string, validator) {
			if !requireResolved && v.Authorization.V == nil {
				return "authorization", &noopT{}
			}
			return "authorization", &v.Authorization
		},
		func(v *Flow) (string, validator) {
			if !requireResolved && v.Environment.V == nil {
				return "environment", &noopT{}
			}
			return "environment", &v.Environment
		},
	); err != nil {
		return err
	}
	return this.validateDiscoverySlug()
}

func (this *Flow) UnmarshalYAML(node *yaml.Node) error {
	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if err := func(target *Flow, node *yaml.Node) error {
		if err := rejectUnknownConfigurationFields(node, target); err != nil {
			return err
		}
		// Decode the effective fields first so YAML merge keys cannot hide a null
		// transport block, for which yaml would skip its UnmarshalYAML method.
		fields, err := effectiveHttpFields(node)
		if err != nil {
			return err
		}
		if value, exists := fields["auditlog"]; exists && value.Tag != "!!str" && value.Tag != "!!null" {
			return reportYamlRelatedErrf(&value, "[auditlog] must be a string reference")
		}
		for _, key := range []string{"ssh", "http"} {
			value, exists := fields[key]
			if !exists {
				continue
			}
			if value.Kind == yaml.AliasNode && value.Alias != nil {
				value = *value.Alias
			}
			if value.Kind != yaml.MappingNode {
				return reportYamlRelatedErrf(&value, "[%s] must be a mapping", key)
			}
		}
		type raw Flow
		return node.Decode((*raw)(target))
	}(this, node); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	// Missing values and references require the complete root context. Typed
	// inline values have already been decoded and validated and never fall back.
	if err := this.trim(false); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	return nil
}

func (this Flow) MarshalYAML() (any, error) {
	type raw Flow
	if this.auditlogResolved && this.Auditlog == this.resolvedAuditlog {
		this.Auditlog = ""
	}
	return raw(this), nil
}

func (this Flow) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Flow:
		return this.isEqualTo(&v)
	case *Flow:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Flow) isEqualTo(other *Flow) bool {
	if other == nil {
		return false
	}
	configuredAuditlog := func(flow Flow) AuditlogName {
		if flow.auditlogResolved && flow.Auditlog == flow.resolvedAuditlog {
			return ""
		}
		return flow.Auditlog
	}
	return isEqual(&this.Name, &other.Name) &&
		isEqual(&this.Auditlog, &other.Auditlog) &&
		configuredAuditlog(this) == configuredAuditlog(*other) &&
		this.Ssh.IsEqualTo(other.Ssh) && this.Http.IsEqualTo(other.Http) &&
		this.DiscoverAsSlug == other.DiscoverAsSlug &&
		isEqual(&this.Requirement, &other.Requirement) &&
		isEqual(&this.Authorization, &other.Authorization) &&
		isEqual(&this.Environment, &other.Environment)
}

// Flows defines a set of Flow instances.
type Flows []Flow

func (this *Flows) SetDefaults() error {
	return setSliceDefaults(this) // Empty, be default.
}

func (this Flows) IsZero() bool {
	return len(this) == 0
}

func (this *Flows) Trim() error {
	if err := trimSlice(this); err != nil {
		return err
	}
	return this.validateUniqueNames()
}

func (this Flows) Validate() error {
	if err := this.validateUniqueNames(); err != nil {
		return err
	}
	return validateSlice(this)
}

func (this Flows) validateUniqueNames() error {
	indices := make(map[FlowName]int, len(this))
	for i, flow := range this {
		if previous, exists := indices[flow.Name]; exists {
			return fmt.Errorf("[%d][name] duplicates [%d][name] %q", i, previous, flow.Name)
		}
		indices[flow.Name] = i
	}
	return nil
}

func (this *Flows) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return reportYamlRelatedErrf(node, "must be a list of flows")
	}
	for _, item := range node.Content {
		if item.Kind == yaml.AliasNode && item.Alias != nil {
			item = item.Alias
		}
		if item.Kind != yaml.MappingNode {
			return reportYamlRelatedErrf(item, "flow must be a mapping")
		}
	}
	// Clear the entries before...
	*this = Flows{}
	type raw Flows
	if err := node.Decode((*raw)(this)); err != nil {
		return err
	}
	return this.validateUniqueNames()
}

func (this Flows) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Flows:
		return this.isEqualTo(&v)
	case *Flows:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Flows) isEqualTo(other *Flows) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		if !tv.IsEqualTo((*other)[i]) {
			return false
		}
	}
	return true
}
