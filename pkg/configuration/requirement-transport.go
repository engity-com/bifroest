package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

type RequirementSsh struct {
	IncludedRequestingName common.Regexp `yaml:"includedRequestingName,omitempty"`
	ExcludedRequestingName common.Regexp `yaml:"excludedRequestingName,omitempty"`
}

func (this *RequirementSsh) SetDefaults() error {
	*this = RequirementSsh{}
	return nil
}
func (this *RequirementSsh) Trim() error { return this.Validate() }
func (*RequirementSsh) Validate() error  { return nil }
func (this RequirementSsh) IsZero() bool {
	return this.IncludedRequestingName.IsZero() && this.ExcludedRequestingName.IsZero()
}
func (this RequirementSsh) MatchesName(name string) bool {
	return matchesRequirement(this.IncludedRequestingName, this.ExcludedRequestingName, name)
}
func (this *RequirementSsh) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *RequirementSsh, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "includedRequestingName", "excludedRequestingName"); err != nil {
			return err
		}
		type raw RequirementSsh
		return node.Decode((*raw)(target))
	})
}
func (this RequirementSsh) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case RequirementSsh:
		return this.isEqualTo(&value)
	case *RequirementSsh:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}
func (this RequirementSsh) isEqualTo(other *RequirementSsh) bool {
	return this.IncludedRequestingName.IsEqualTo(other.IncludedRequestingName) && this.ExcludedRequestingName.IsEqualTo(other.ExcludedRequestingName)
}

type RequirementHttp struct {
	IncludedRequestingName common.Regexp `yaml:"includedRequestingName,omitempty"`
	ExcludedRequestingName common.Regexp `yaml:"excludedRequestingName,omitempty"`
	IncludedHost           common.Regexp `yaml:"includedHost,omitempty"`
	ExcludedHost           common.Regexp `yaml:"excludedHost,omitempty"`
	IncludedSlug           common.Regexp `yaml:"includedSlug,omitempty"`
	ExcludedSlug           common.Regexp `yaml:"excludedSlug,omitempty"`
}

func (this *RequirementHttp) SetDefaults() error {
	*this = RequirementHttp{}
	return nil
}
func (this *RequirementHttp) Trim() error { return this.Validate() }
func (*RequirementHttp) Validate() error  { return nil }
func (this RequirementHttp) IsZero() bool {
	return this.IncludedRequestingName.IsZero() && this.ExcludedRequestingName.IsZero() &&
		this.IncludedHost.IsZero() && this.ExcludedHost.IsZero() && this.IncludedSlug.IsZero() && this.ExcludedSlug.IsZero()
}
func (this RequirementHttp) MatchesName(name string) bool {
	return matchesRequirement(this.IncludedRequestingName, this.ExcludedRequestingName, name)
}
func (this RequirementHttp) MatchesHost(host string) bool {
	return matchesRequirement(this.IncludedHost, this.ExcludedHost, host)
}
func (this RequirementHttp) MatchesSlug(slug string) bool {
	return matchesRequirement(this.IncludedSlug, this.ExcludedSlug, slug)
}
func (this *RequirementHttp) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *RequirementHttp, node *yaml.Node) error {
		if err := rejectUnknownAuditlogFields(node, "includedRequestingName", "excludedRequestingName", "includedHost", "excludedHost", "includedSlug", "excludedSlug"); err != nil {
			return err
		}
		type raw RequirementHttp
		return node.Decode((*raw)(target))
	})
}
func (this RequirementHttp) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case RequirementHttp:
		return this.isEqualTo(&value)
	case *RequirementHttp:
		return value != nil && this.isEqualTo(value)
	default:
		return false
	}
}
func (this RequirementHttp) isEqualTo(other *RequirementHttp) bool {
	return this.IncludedRequestingName.IsEqualTo(other.IncludedRequestingName) &&
		this.ExcludedRequestingName.IsEqualTo(other.ExcludedRequestingName) &&
		this.IncludedHost.IsEqualTo(other.IncludedHost) && this.ExcludedHost.IsEqualTo(other.ExcludedHost) &&
		this.IncludedSlug.IsEqualTo(other.IncludedSlug) && this.ExcludedSlug.IsEqualTo(other.ExcludedSlug)
}

func matchesRequirement(included, excluded common.Regexp, value string) bool {
	return (included.IsZero() || included.MatchString(value)) && (excluded.IsZero() || !excluded.MatchString(value))
}
