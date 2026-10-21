package configuration

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

// Only the display message is redacted. Typed causes remain available to code
// through errors.Is/errors.As, but must not be logged separately as diagnostics.
type configurationCredentialError struct {
	field  string
	reason string
	cause  error
}

func (this *configurationCredentialError) Error() string {
	return fmt.Sprintf("[%s] %s (***redacted***)", this.field, this.reason)
}

func (this *configurationCredentialError) Unwrap() error { return this.cause }

func sensitiveConfigurationField(target any, name string) (reflect.StructField, bool) {
	typ := reflect.TypeOf(target)
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	for index := range typ.NumField() {
		field := typ.Field(index)
		key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if key == name && field.Tag.Get("sensitive") == "true" {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

func configurationFieldError(target any, name string, err error) error {
	if field, sensitive := sensitiveConfigurationField(target, name); sensitive {
		return &configurationCredentialError{field: name, reason: credentialErrorReason(field.Type, err), cause: err}
	}
	return fmt.Errorf("[%s] %w", name, err)
}

func credentialErrorReason(typ reflect.Type, err error) string {
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if cause.Error() == "required but absent" {
			return "required but absent"
		}
	}
	switch typ {
	case reflect.TypeFor[crypto.Password]():
		return "illegal password"
	case reflect.TypeFor[crypto.PasswordFile]():
		return "illegal password file"
	case reflect.TypeFor[template.String]():
		return "invalid credential template"
	case reflect.TypeFor[EnvironmentVariables]():
		return "invalid environment variables"
	default:
		return "invalid credential value"
	}
}

// decodeConfigurationFields decodes a raw configuration struct once, intercepting
// errors at sensitive fields before yaml can concatenate them with other errors.
// It preserves defaults and uses the original field parsers, including file-backed
// credentials. Nothing is evaluated, provisioned or read a second time.
func decodeConfigurationFields(node *yaml.Node, target any) error {
	value := reflect.ValueOf(target).Elem()
	typ := value.Type()
	fields := make([]reflect.StructField, typ.NumField())
	for index := range fields {
		fields[index] = typ.Field(index)
		if fields[index].Tag.Get("sensitive") == "true" {
			fields[index].Type = reflect.TypeFor[credentialYAMLValue]()
		}
	}
	shadow := reflect.New(reflect.StructOf(fields))
	for index, field := range fields {
		if !field.IsExported() {
			continue
		}
		if field.Tag.Get("sensitive") == "true" {
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			shadow.Elem().Field(index).Set(reflect.ValueOf(credentialYAMLValue{
				name: name, target: value.Field(index).Addr().Interface(),
			}))
		} else {
			shadow.Elem().Field(index).Set(value.Field(index))
		}
	}
	err := node.Decode(shadow.Interface())
	for index, field := range fields {
		if field.IsExported() && field.Tag.Get("sensitive") != "true" {
			value.Field(index).Set(shadow.Elem().Field(index))
		}
	}
	return err
}

type credentialYAMLValue struct {
	name   string
	target any
}

func (this *credentialYAMLValue) UnmarshalYAML(node *yaml.Node) error {
	if err := node.Decode(this.target); err != nil {
		return reportYamlRelatedErr(node, &configurationCredentialError{
			field: this.name, reason: credentialErrorReason(reflect.TypeOf(this.target).Elem(), err), cause: err,
		})
	}
	return nil
}
