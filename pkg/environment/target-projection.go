package environment

import (
	"slices"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

// TargetProjection is an immutable snapshot of the fields used by the production
// session-target resolver. Fields retain their string, bool or []string types;
// list values are copied on access. No request context or runtime client is kept.
//
// This is a target-selection projection, not a successful login, a provisioned
// resource or a complete policy result. For example, an empty container user is
// still an unresolved image-dependent selector, not an assumed root account.
// These values can be sensitive. They are not a public report format and must not
// be dumped into diagnostics or exposed to Lua without a controlled data view.
type TargetProjection struct {
	kind   string
	fields map[string]any
	target session.Target
}

func (this TargetProjection) Kind() string { return this.kind }

// Field distinguishes an absent field from a present false, empty string or
// empty list. Lists follow the existing target resolver's nil-to-empty
// normalization; no numeric or boolean string conversion is performed.
func (this TargetProjection) Field(name string) (any, bool) {
	value, present := this.fields[name]
	if list, ok := value.([]string); ok {
		return slices.Clone(list), present
	}
	return value, present
}

// SessionTarget returns the existing v1 fingerprint of this snapshot. A zero
// projection is invalid rather than an implicitly successful empty target.
func (this TargetProjection) SessionTarget() (session.Target, error) {
	if err := this.target.Validate(); err != nil {
		return "", errors.System.Newf("%w", err)
	}
	return this.target, nil
}

func newTargetProjectionFields(ctx Context) *targetFields {
	fields := newTargetFields(ctx)
	fields.projected = make(map[string]any)
	return fields
}

func (this *targetFields) projection(kind string) (TargetProjection, error) {
	target, err := this.target(kind)
	if err != nil {
		return TargetProjection{}, err
	}
	fields := make(map[string]any, len(this.values))
	for name, value := range this.values {
		if name != "resolver" { // The internal digest marker is not a target field.
			fields[name] = value
		}
	}
	for name, value := range this.projected {
		if list, ok := value.([]string); ok {
			value = slices.Clone(list)
		}
		fields[name] = value
	}
	return TargetProjection{kind: kind, fields: fields, target: target}, nil
}
