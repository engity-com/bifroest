package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

var (
	DefaultRequirementIncludedRequestingName = common.MustNewRegexp("")
	DefaultRequirementExcludedRequestingName = common.MustNewRegexp("")
)

type Requirement struct {
	IncludedRequestingName common.Regexp   `yaml:"includedRequestingName,omitempty"`
	ExcludedRequestingName common.Regexp   `yaml:"excludedRequestingName,omitempty"`
	Ssh                    RequirementSsh  `yaml:"ssh,omitempty"`
	Http                   RequirementHttp `yaml:"http,omitempty"`
}

func (this *Requirement) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("includedRequestingName", func(v *Requirement) *common.Regexp { return &v.IncludedRequestingName }, DefaultRequirementIncludedRequestingName),
		fixedDefault("excludedRequestingName", func(v *Requirement) *common.Regexp { return &v.ExcludedRequestingName }, DefaultRequirementExcludedRequestingName),
		func(v *Requirement) (string, defaulter) { return "ssh", &v.Ssh },
		func(v *Requirement) (string, defaulter) { return "http", &v.Http },
	)
}

func (this *Requirement) Trim() error {
	return trim(this,
		noopTrim[Requirement]("includedRequestingName"),
		noopTrim[Requirement]("excludedRequestingName"),
		func(v *Requirement) (string, trimmer) { return "ssh", &v.Ssh },
		func(v *Requirement) (string, trimmer) { return "http", &v.Http },
	)
}

func (this *Requirement) Validate() error {
	return validate(this,
		noopValidate[Requirement]("includedRequestingName"),
		noopValidate[Requirement]("excludedRequestingName"),
		func(v *Requirement) (string, validator) { return "ssh", &v.Ssh },
		func(v *Requirement) (string, validator) { return "http", &v.Http },
	)
}

func (this *Requirement) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Requirement, node *yaml.Node) error {
		type raw Requirement
		return node.Decode((*raw)(target))
	})
}

func (this Requirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Requirement:
		return this.isEqualTo(&v)
	case *Requirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Requirement) isEqualTo(other *Requirement) bool {
	return isEqual(&this.IncludedRequestingName, &other.IncludedRequestingName) &&
		isEqual(&this.ExcludedRequestingName, &other.ExcludedRequestingName) &&
		this.Ssh.IsEqualTo(other.Ssh) && this.Http.IsEqualTo(other.Http)
}

func (this Requirement) MatchesSsh(name string) bool {
	return matchesRequirement(this.IncludedRequestingName, this.ExcludedRequestingName, name) && this.Ssh.MatchesName(name)
}

func (this Requirement) MatchesHttp(name, host, slug string) bool {
	return matchesRequirement(this.IncludedRequestingName, this.ExcludedRequestingName, name) &&
		this.Http.MatchesName(name) && this.Http.MatchesHost(host) && this.Http.MatchesSlug(slug)
}
