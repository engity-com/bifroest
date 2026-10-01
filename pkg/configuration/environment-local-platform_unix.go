//go:build darwin

package configuration

import (
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/user"
)

const (
	DefaultEnvironmentLocalTargetAccountAllowUidZero                 = false
	DefaultEnvironmentLocalTargetAccountAllowSystemAccounts          = false
	DefaultEnvironmentLocalTargetAccountAllowAdministrators          = false
	DefaultEnvironmentLocalTargetAccountAllowNonLoginShell           = false
	DefaultEnvironmentLocalTargetAccountAllowUnsafeNoneAuthorization = false
)

type EnvironmentLocalPlatform struct {
	TargetAccountPolicy EnvironmentLocalTargetAccountPolicy `yaml:"targetAccountPolicy,omitempty"`
}

func (this *EnvironmentLocalPlatform) SetDefaults() error {
	return setDefaults(this,
		func(v *EnvironmentLocalPlatform) (string, defaulter) {
			return "targetAccountPolicy", &v.TargetAccountPolicy
		},
	)
}

func (this *EnvironmentLocalPlatform) Trim() error {
	return trim(this,
		func(v *EnvironmentLocalPlatform) (string, trimmer) {
			return "targetAccountPolicy", &v.TargetAccountPolicy
		},
	)
}

func (this *EnvironmentLocalPlatform) Validate() error {
	return validate(this,
		func(v *EnvironmentLocalPlatform) (string, validator) {
			return "targetAccountPolicy", &v.TargetAccountPolicy
		},
	)
}

func (this EnvironmentLocalPlatform) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case EnvironmentLocalPlatform:
		return this.TargetAccountPolicy.IsEqualTo(v.TargetAccountPolicy)
	case *EnvironmentLocalPlatform:
		return v != nil && this.TargetAccountPolicy.IsEqualTo(v.TargetAccountPolicy)
	default:
		return false
	}
}

type EnvironmentLocalTargetAccountPolicy struct {
	AllowUidZero                 bool `yaml:"allowUidZero,omitempty"`
	AllowSystemAccounts          bool `yaml:"allowSystemAccounts,omitempty"`
	AllowAdministrators          bool `yaml:"allowAdministrators,omitempty"`
	AllowNonLoginShell           bool `yaml:"allowNonLoginShell,omitempty"`
	AllowUnsafeNoneAuthorization bool `yaml:"allowUnsafeNoneAuthorization,omitempty"`

	AllowedNames  []string       `yaml:"allowedNames,omitempty"`
	DeniedNames   []string       `yaml:"deniedNames,omitempty"`
	AllowedUids   []user.Id      `yaml:"allowedUids,omitempty"`
	DeniedUids    []user.Id      `yaml:"deniedUids,omitempty"`
	AllowedGroups []string       `yaml:"allowedGroups,omitempty"`
	DeniedGroups  []string       `yaml:"deniedGroups,omitempty"`
	AllowedGids   []user.GroupId `yaml:"allowedGids,omitempty"`
	DeniedGids    []user.GroupId `yaml:"deniedGids,omitempty"`
}

func (this *EnvironmentLocalTargetAccountPolicy) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("allowUidZero", func(v *EnvironmentLocalTargetAccountPolicy) *bool { return &v.AllowUidZero }, DefaultEnvironmentLocalTargetAccountAllowUidZero),
		fixedDefault("allowSystemAccounts", func(v *EnvironmentLocalTargetAccountPolicy) *bool { return &v.AllowSystemAccounts }, DefaultEnvironmentLocalTargetAccountAllowSystemAccounts),
		fixedDefault("allowAdministrators", func(v *EnvironmentLocalTargetAccountPolicy) *bool { return &v.AllowAdministrators }, DefaultEnvironmentLocalTargetAccountAllowAdministrators),
		fixedDefault("allowNonLoginShell", func(v *EnvironmentLocalTargetAccountPolicy) *bool { return &v.AllowNonLoginShell }, DefaultEnvironmentLocalTargetAccountAllowNonLoginShell),
		fixedDefault("allowUnsafeNoneAuthorization", func(v *EnvironmentLocalTargetAccountPolicy) *bool { return &v.AllowUnsafeNoneAuthorization }, DefaultEnvironmentLocalTargetAccountAllowUnsafeNoneAuthorization),
		fixedDefault("allowedNames", func(v *EnvironmentLocalTargetAccountPolicy) *[]string { return &v.AllowedNames }, []string(nil)),
		fixedDefault("deniedNames", func(v *EnvironmentLocalTargetAccountPolicy) *[]string { return &v.DeniedNames }, []string(nil)),
		fixedDefault("allowedUids", func(v *EnvironmentLocalTargetAccountPolicy) *[]user.Id { return &v.AllowedUids }, []user.Id(nil)),
		fixedDefault("deniedUids", func(v *EnvironmentLocalTargetAccountPolicy) *[]user.Id { return &v.DeniedUids }, []user.Id(nil)),
		fixedDefault("allowedGroups", func(v *EnvironmentLocalTargetAccountPolicy) *[]string { return &v.AllowedGroups }, []string(nil)),
		fixedDefault("deniedGroups", func(v *EnvironmentLocalTargetAccountPolicy) *[]string { return &v.DeniedGroups }, []string(nil)),
		fixedDefault("allowedGids", func(v *EnvironmentLocalTargetAccountPolicy) *[]user.GroupId { return &v.AllowedGids }, []user.GroupId(nil)),
		fixedDefault("deniedGids", func(v *EnvironmentLocalTargetAccountPolicy) *[]user.GroupId { return &v.DeniedGids }, []user.GroupId(nil)),
	)
}

func (this *EnvironmentLocalTargetAccountPolicy) Trim() error {
	return trim(this,
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowUidZero"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowSystemAccounts"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowAdministrators"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowNonLoginShell"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowUnsafeNoneAuthorization"),
		func(v *EnvironmentLocalTargetAccountPolicy) (string, trimmer) {
			return "allowedNames", targetAccountStrings(v.AllowedNames)
		},
		func(v *EnvironmentLocalTargetAccountPolicy) (string, trimmer) {
			return "deniedNames", targetAccountStrings(v.DeniedNames)
		},
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowedUids"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("deniedUids"),
		func(v *EnvironmentLocalTargetAccountPolicy) (string, trimmer) {
			return "allowedGroups", targetAccountStrings(v.AllowedGroups)
		},
		func(v *EnvironmentLocalTargetAccountPolicy) (string, trimmer) {
			return "deniedGroups", targetAccountStrings(v.DeniedGroups)
		},
		noopTrim[EnvironmentLocalTargetAccountPolicy]("allowedGids"),
		noopTrim[EnvironmentLocalTargetAccountPolicy]("deniedGids"),
	)
}

func (this *EnvironmentLocalTargetAccountPolicy) Validate() error {
	return validate(this,
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowUidZero"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowSystemAccounts"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowAdministrators"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowNonLoginShell"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowUnsafeNoneAuthorization"),
		func(v *EnvironmentLocalTargetAccountPolicy) (string, validator) {
			return "allowedNames", targetAccountStrings(v.AllowedNames)
		},
		func(v *EnvironmentLocalTargetAccountPolicy) (string, validator) {
			return "deniedNames", targetAccountStrings(v.DeniedNames)
		},
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowedUids"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("deniedUids"),
		func(v *EnvironmentLocalTargetAccountPolicy) (string, validator) {
			return "allowedGroups", targetAccountStrings(v.AllowedGroups)
		},
		func(v *EnvironmentLocalTargetAccountPolicy) (string, validator) {
			return "deniedGroups", targetAccountStrings(v.DeniedGroups)
		},
		noopValidate[EnvironmentLocalTargetAccountPolicy]("allowedGids"),
		noopValidate[EnvironmentLocalTargetAccountPolicy]("deniedGids"),
	)
}

func (this *EnvironmentLocalTargetAccountPolicy) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocalTargetAccountPolicy, node *yaml.Node) error {
		type raw EnvironmentLocalTargetAccountPolicy
		return node.Decode((*raw)(target))
	})
}

type targetAccountStrings []string

func (this targetAccountStrings) Trim() error {
	for i := range this {
		this[i] = strings.TrimSpace(this[i])
	}
	return nil
}

func (this targetAccountStrings) Validate() error {
	for i, value := range this {
		if value == "" {
			return fmt.Errorf("[%d] required but absent", i)
		}
	}
	return nil
}

func (this EnvironmentLocalTargetAccountPolicy) IsEqualTo(other any) bool {
	var candidate *EnvironmentLocalTargetAccountPolicy
	switch v := other.(type) {
	case EnvironmentLocalTargetAccountPolicy:
		candidate = &v
	case *EnvironmentLocalTargetAccountPolicy:
		candidate = v
	default:
		return false
	}
	return candidate != nil &&
		this.AllowUidZero == candidate.AllowUidZero &&
		this.AllowSystemAccounts == candidate.AllowSystemAccounts &&
		this.AllowAdministrators == candidate.AllowAdministrators &&
		this.AllowNonLoginShell == candidate.AllowNonLoginShell &&
		this.AllowUnsafeNoneAuthorization == candidate.AllowUnsafeNoneAuthorization &&
		slices.Equal(this.AllowedNames, candidate.AllowedNames) &&
		slices.Equal(this.DeniedNames, candidate.DeniedNames) &&
		slices.Equal(this.AllowedUids, candidate.AllowedUids) &&
		slices.Equal(this.DeniedUids, candidate.DeniedUids) &&
		slices.Equal(this.AllowedGroups, candidate.AllowedGroups) &&
		slices.Equal(this.DeniedGroups, candidate.DeniedGroups) &&
		slices.Equal(this.AllowedGids, candidate.AllowedGids) &&
		slices.Equal(this.DeniedGids, candidate.DeniedGids)
}
