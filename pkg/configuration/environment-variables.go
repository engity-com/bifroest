package configuration

import (
	"fmt"
	"sort"
	"strings"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

type EnvironmentVariableName string

func (this EnvironmentVariableName) Validate() error {
	if this == "" {
		return fmt.Errorf("required but absent")
	}
	for i, r := range this {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return fmt.Errorf("illegal environment variable name")
	}
	return nil
}

type EnvironmentVariables map[EnvironmentVariableName]template.String

func (this *EnvironmentVariables) SetDefaults() error {
	*this = EnvironmentVariables{}
	return nil
}

func (this *EnvironmentVariables) Trim() error {
	return this.Validate()
}

func (this EnvironmentVariables) Validate() error {
	keys := make([]EnvironmentVariableName, 0, len(this))
	for key := range this {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return fmt.Errorf("[%s] %w", key, err)
		}
		value := this[key]
		if err := value.Validate(); err != nil {
			return fmt.Errorf("[%s] %w", key, err)
		}
	}
	return nil
}

func (this EnvironmentVariables) IsZero() bool { return len(this) == 0 }

func (this EnvironmentVariables) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case EnvironmentVariables:
		return this.isEqualTo(v)
	case *EnvironmentVariables:
		return v != nil && this.isEqualTo(*v)
	default:
		return false
	}
}

func (this EnvironmentVariables) isEqualTo(other EnvironmentVariables) bool {
	if len(this) != len(other) {
		return false
	}
	for key, value := range this {
		candidate, ok := other[key]
		if !ok || !value.IsEqualTo(candidate) {
			return false
		}
	}
	return true
}

func (this EnvironmentVariables) Render(data any) (sys.EnvVars, error) {
	result := make(sys.EnvVars, len(this))
	for key, value := range this {
		rendered, err := value.Render(data)
		if err != nil {
			return nil, fmt.Errorf("[%s] %w", key, err)
		}
		if strings.IndexByte(rendered, 0) >= 0 {
			return nil, fmt.Errorf("[%s] environment variable value contains NUL", key)
		}
		result[string(key)] = rendered
	}
	return result, nil
}
