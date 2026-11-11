package configuration

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Environments and Authorizations contain definitions, never reference chains.
type Environments map[string]Environment
type Authorizations map[string]Authorization

func (this *Environments) SetDefaults() error   { *this = nil; return nil }
func (this *Authorizations) SetDefaults() error { *this = nil; return nil }

func definitionKeys[V any, M ~map[string]V](values M) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func validateDefinitionName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("definition name must not be empty")
	}
	return nil
}

func validateDefinitions[V any, M ~map[string]V](values M, check func(*V) error) error {
	for _, name := range definitionKeys(values) {
		if err := validateDefinitionName(name); err != nil {
			return err
		}
		value := values[name]
		if err := check(&value); err != nil {
			return fmt.Errorf("[%s] %w", name, err)
		}
	}
	return nil
}

func (this Environments) Validate() error {
	return validateDefinitions(this, func(value *Environment) error {
		if value.Reference != "" || value.resolved {
			return fmt.Errorf("must be a typed inline mapping, not a reference")
		}
		return value.Validate()
	})
}

func (this Authorizations) Validate() error {
	return validateDefinitions(this, func(value *Authorization) error {
		if value.Reference != "" || value.resolved {
			return fmt.Errorf("must be a typed inline mapping, not a reference")
		}
		return value.Validate()
	})
}

func (this *Environments) Trim() error {
	for _, name := range definitionKeys(*this) {
		value := (*this)[name]
		if err := value.Trim(); err != nil {
			return fmt.Errorf("[%s] %w", name, err)
		}
		(*this)[name] = value
	}
	return this.Validate()
}

func (this *Authorizations) Trim() error {
	for _, name := range definitionKeys(*this) {
		value := (*this)[name]
		if err := value.Trim(); err != nil {
			return fmt.Errorf("[%s] %w", name, err)
		}
		(*this)[name] = value
	}
	return this.Validate()
}

func decodeDefinitions[V any, M ~map[string]V](node *yaml.Node, target *M) error {
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	result := make(M, len(fields))
	for _, name := range definitionKeys(fields) {
		value := fields[name]
		if err := validateDefinitionName(name); err != nil {
			return reportYamlRelatedErr(&value, err)
		}
		if _, err := effectiveHttpFields(&value); err != nil {
			return reportYamlRelatedErrf(&value, "[%s] must be a typed inline mapping", name)
		}
		// The map key identifies the definition. Its provider owns the value's
		// schema: local.name and kubernetes.name are target settings, while the
		// removed Auditlog.name and unsupported provider fields remain invalid.
		var decoded V
		if err := value.Decode(&decoded); err != nil {
			return reportYamlRelatedErrf(&value, "[%s] %w", name, err)
		}
		result[name] = decoded
	}
	*target = result
	return nil
}

func (this *Environments) UnmarshalYAML(node *yaml.Node) error {
	return decodeDefinitions(node, this)
}

func (this *Authorizations) UnmarshalYAML(node *yaml.Node) error {
	return decodeDefinitions(node, this)
}

func (this Environments) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return map[string]Environment(this), nil
}

func (this Authorizations) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return map[string]Authorization(this), nil
}

func equalDefinitions[V equaler, M ~map[string]V](left, right M) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		other, exists := right[name]
		if !exists || !value.IsEqualTo(other) {
			return false
		}
	}
	return true
}

func (this Environments) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case Environments:
		return equalDefinitions(this, value)
	case *Environments:
		return value != nil && equalDefinitions(this, *value)
	default:
		return false
	}
}

func (this Authorizations) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case Authorizations:
		return equalDefinitions(this, value)
	case *Authorizations:
		return value != nil && equalDefinitions(this, *value)
	default:
		return false
	}
}

// rejectUnknownConfigurationFields also checks effective YAML merge fields.
// Provider schemas come from their exported YAML fields, not a second registry.
func rejectUnknownConfigurationFields(node *yaml.Node, target any, extra ...string) error {
	known := make(map[string]bool)
	for _, name := range extra {
		known[name] = true
	}
	var collect func(reflect.Type)
	collect = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for index := range typ.NumField() {
			field := typ.Field(index)
			if !field.IsExported() {
				continue
			}
			name, options, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if slices.Contains(strings.Split(options, ","), "inline") {
				collect(field.Type)
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name)
			}
			known[name] = true
		}
	}
	collect(reflect.TypeOf(target))
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	for _, name := range definitionKeys(fields) {
		if !known[name] {
			value := fields[name]
			return reportYamlRelatedErrf(&value, "field %s not found", name)
		}
	}
	return nil
}

// Copy exported configuration data without serializing secrets or applying YAML
// defaults again. Private implementation data (e.g. compiled templates) is
// immutable; mutable provider pointers, slices and maps belong to each flow.
func cloneConfigurationValue[T any](value T) T {
	return cloneConfigurationReflect(reflect.ValueOf(&value).Elem()).Interface().(T)
}

func cloneConfigurationReflect(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return value
		}
		result := reflect.New(value.Type().Elem())
		result.Elem().Set(cloneConfigurationReflect(value.Elem()))
		return result
	case reflect.Interface:
		if value.IsNil() {
			return value
		}
		result := reflect.New(value.Type()).Elem()
		result.Set(cloneConfigurationReflect(value.Elem()))
		return result
	case reflect.Struct:
		result := reflect.New(value.Type()).Elem()
		result.Set(value)
		for index := range value.NumField() {
			if value.Type().Field(index).IsExported() {
				result.Field(index).Set(cloneConfigurationReflect(value.Field(index)))
			}
		}
		return result
	case reflect.Slice:
		if value.IsNil() {
			return value
		}
		result := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for index := range value.Len() {
			result.Index(index).Set(cloneConfigurationReflect(value.Index(index)))
		}
		return result
	case reflect.Map:
		if value.IsNil() {
			return value
		}
		result := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			result.SetMapIndex(iterator.Key(), cloneConfigurationReflect(iterator.Value()))
		}
		return result
	default:
		return value
	}
}
