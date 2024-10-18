package configuration

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type defaulter interface {
	SetDefaults() error
}

type defaulterFunc func() error

func (f defaulterFunc) SetDefaults() error {
	return f()
}

func setDefaults[T any](target *T, fs ...func(*T) (string, defaulter)) error {
	for _, f := range fs {
		n, d := f(target)
		if err := d.SetDefaults(); err != nil {
			if n == "" {
				return err
			}
			return fmt.Errorf("[%s] %w", n, err)
		}
	}
	return nil
}

func setSliceDefaults[T any, S ~[]T](target *S, initialValues ...T) error {
	*target = initialValues
	for i, v := range *target {
		var pv any = &v
		if err := pv.(defaulter).SetDefaults(); err != nil {
			return fmt.Errorf("[%d] %w", i, err)
		}
		(*target)[i] = v
	}
	return nil
}

type fixedDefaulter[T any] struct {
	target *T
	value  T
}

func (this *fixedDefaulter[T]) SetDefaults() error {
	*this.target = this.value
	return nil
}

func fixedDefault[T any, V any](name string, target func(*T) *V, value V) func(*T) (string, defaulter) {
	return func(t *T) (string, defaulter) {
		return name, &fixedDefaulter[V]{target(t), value}
	}
}

type trimmer interface {
	Trim() error
}

func trim[T validator](target T, fs ...func(T) (string, trimmer)) error {
	for _, f := range fs {
		n, d := f(target)
		if err := d.Trim(); err != nil {
			if n == "" {
				return err
			}
			return fmt.Errorf("[%s] %w", n, err)
		}
	}
	return target.Validate()
}

func trimSlice[T any, S ~[]T](target *S) error {
	for i, v := range *target {
		var pv any = &v
		if err := pv.(trimmer).Trim(); err != nil {
			return fmt.Errorf("[%d] %w", i, err)
		}
		(*target)[i] = v
	}
	return nil
}

type stringTrimmer struct {
	target *string
}

func (this *stringTrimmer) Trim() error {
	*this.target = strings.TrimSpace(*this.target)
	return nil
}

type validator interface {
	Validate() error
}

func validate[T any](target T, fs ...func(T) (string, validator)) error {
	for _, f := range fs {
		n, d := f(target)
		if d == nil || nil == (validator)(nil) {
			continue
		}
		if err := d.Validate(); err != nil {
			if n == "" {
				return err
			}
			return fmt.Errorf("[%s] %w", n, err)
		}
	}
	return nil
}

func validateSlice[T any, S ~[]T](target S) error {
	for i, v := range target {
		var pv any = &v
		if err := (pv).(validator).Validate(); err != nil {
			return fmt.Errorf("[%d] %w", i, err)
		}
	}
	return nil
}

type notEmptyStringValidator struct {
	target *string
}

func (this *notEmptyStringValidator) Validate() error {
	if len(*this.target) == 0 {
		return fmt.Errorf("required but absent")
	}
	return nil
}

func notEmptyStringValidate[T any](name string, target func(*T) *string) func(*T) (string, validator) {
	return func(t *T) (string, validator) {
		return name, &notEmptyStringValidator{target(t)}
	}
}

type zerorer interface {
	IsZero() bool
}

type notZeroValidator struct {
	target zerorer
}

func (this *notZeroValidator) Validate() error {
	if this.target.IsZero() {
		return fmt.Errorf("required but absent")
	}
	return nil
}

func notZeroValidate[T any, V zerorer](name string, target func(*T) *V) func(*T) (string, validator) {
	return func(t *T) (string, validator) {
		return name, &notZeroValidator{*target(t)}
	}
}

type unmarshalYAMLTarget interface {
	defaulter
	trimmer
}

func unmarshalYAML[T unmarshalYAMLTarget](target T, node *yaml.Node, decoder func(target T, node *yaml.Node) error) error {
	if err := target.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if err := decoder(target, node); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	if err := target.Trim(); err != nil {
		return reportYamlRelatedErr(node, err)
	}
	return nil
}

func reportYamlRelatedErr(node *yaml.Node, err error) error {
	var ole *LocationError
	if errors.As(err, &ole) {
		return err
	}
	return &LocationError{
		Line:   node.Line,
		Column: node.Column,
		Cause:  err,
	}
}

func reportYamlRelatedErrf(node *yaml.Node, message string, args ...any) error {
	return reportYamlRelatedErr(node, fmt.Errorf(message, args...))
}

type LocationError struct {
	File   string
	Line   int
	Column int
	Cause  error
}

func (this *LocationError) Error() string {
	if f := this.File; f != "" {
		if l := this.Line; l >= 0 {
			if c := this.Column; c >= 0 {
				return fmt.Sprintf("[%s:%d:%d] %v", f, l, c, this.Cause)
			}
			return fmt.Sprintf("[%s:%d] %v", f, l, this.Cause)
		}
		return fmt.Sprintf("[%s] %v", f, this.Cause)
	}

	if l := this.Line; l >= 0 {
		if c := this.Column; c >= 0 {
			return fmt.Sprintf("[%d:%d] %v", l, c, this.Cause)
		}
		return fmt.Sprintf("[%d] %v", l, this.Cause)
	}

	return fmt.Sprintf("%v", this.Cause)
}

func (this *LocationError) Unwrap() error {
	return this.Cause
}

type noopT struct{}

func (this *noopT) Validate() error {
	return nil
}

func (this *noopT) Trim() error {
	return nil
}

func (this *noopT) SetDefaults() error {
	return nil
}

func noopValidate[T any](name string) func(*T) (string, validator) {
	return func(t *T) (string, validator) {
		return name, &noopT{}
	}
}

func noopTrim[T any](name string) func(*T) (string, trimmer) {
	return func(t *T) (string, trimmer) {
		return name, &noopT{}
	}
}

func noopSetDefault[T any](name string) func(*T) (string, defaulter) {
	return func(t *T) (string, defaulter) {
		return name, &noopT{}
	}
}

type equaler interface {
	IsEqualTo(any) bool
}

func isEqual[T equaler](left, right *T) bool {
	if left == nil && right == nil {
		return true
	}
	if left == nil || right == nil {
		return false
	}
	return (*left).IsEqualTo(*right)
}
