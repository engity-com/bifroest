package environment

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

// SessionTargetResolver describes the effective, server-selected environment.
// It must not provision resources, acquire credentials or open target transports.
// The caller supplies a candidate-specific template context (including session.id).
type SessionTargetResolver interface {
	ResolveSessionTarget(Context) (session.Target, error)
}

// SessionReuseTargetResolver can retain immutable provisioning choices of a
// known live session while still checking today's backend, identity and policy.
// It never imports sessions or changes their persistent ownership.
type SessionReuseTargetResolver interface {
	ResolveSessionReuseTarget(Context, configuration.Environment) (session.Target, error)
}

// SessionTargetResolverFor preserves third-party repositories without guessing
// their target semantics. They continue to use their existing selection path.
func SessionTargetResolverFor(repository Repository, flow configuration.FlowName) (SessionTargetResolver, bool) {
	if facade, ok := repository.(*RepositoryFacade); ok {
		repository = facade.entries[flow]
	}
	resolver, ok := repository.(SessionTargetResolver)
	return resolver, ok
}

func SessionReuseTargetResolverFor(repository Repository, flow configuration.FlowName) (SessionReuseTargetResolver, bool) {
	if facade, ok := repository.(*RepositoryFacade); ok {
		repository = facade.entries[flow]
	}
	resolver, ok := repository.(SessionReuseTargetResolver)
	return resolver, ok
}

// targetFields never propagates template error text: rendered target fields may
// include operator-controlled sensitive values. Only the final digest persists.
type targetFields struct {
	ctx       Context
	values    map[string]string
	projected map[string]any
	err       error
}

func newTargetFields(ctx Context) *targetFields {
	return &targetFields{ctx: ctx, values: map[string]string{"resolver": "environment-v1"}}
}
func (this *targetFields) string(name string, value *template.String) {
	if this.err != nil {
		return
	}
	rendered, err := value.Render(this.ctx)
	if err != nil {
		this.err = sessionTargetError(errors.Config, err, "cannot resolve session target field %s", name)
		return
	}
	this.values[name] = rendered
}
func (this *targetFields) strings(name string, value *template.Strings) {
	if this.err != nil {
		return
	}
	rendered, err := value.Render(this.ctx)
	if err != nil {
		this.err = sessionTargetError(errors.Config, err, "cannot resolve session target field %s", name)
		return
	}
	if rendered == nil {
		rendered = []string{}
	}
	raw, err := json.Marshal(rendered)
	if err != nil {
		this.err = sessionTargetError(errors.System, err, "cannot encode session target field %s", name)
		return
	}
	this.values[name] = string(raw)
	if this.projected != nil {
		this.projected[name] = rendered
	}
}
func (this *targetFields) boolean(name string, value *template.Bool) {
	if this.err != nil {
		return
	}
	rendered, err := value.Render(this.ctx)
	if err != nil {
		this.err = sessionTargetError(errors.Config, err, "cannot resolve session target field %s", name)
		return
	}
	this.values[name] = strconv.FormatBool(rendered)
	if this.projected != nil {
		this.projected[name] = rendered
	}
}
func (this *targetFields) target(kind string) (session.Target, error) {
	if this.err != nil {
		return "", this.err
	}
	if err := this.ctx.Context().Err(); err != nil {
		return "", errors.System.Newf("%w", err)
	}
	target, err := session.NewTarget(kind, this.values)
	if err != nil {
		return "", errors.Config.Newf("%w", err)
	}
	return target, nil
}

// sessionTargetError preserves the first project error type (as Newf does), but
// discards the original message, cause and UserFacing flag. Target inputs may be
// sensitive even when an upstream error was marked user-facing. Only well-known
// context sentinels are safe to retain; arbitrary provider causes must not escape.
func sessionTargetError(fallback errors.Type, cause error, format string, args ...any) *errors.Error {
	if typed, ok := errors.IsError(cause); ok {
		fallback = typed.Type
	} else if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		fallback = errors.System
	}
	result := fallback.Newf(format, args...)
	switch {
	case errors.Is(cause, context.Canceled):
		result.Cause = context.Canceled
	case errors.Is(cause, context.DeadlineExceeded):
		result.Cause = context.DeadlineExceeded
	}
	return result
}

func (this *DummyRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	return newTargetFields(ctx).target("dummy")
}
func (this *ManagementRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	fields := newTargetFields(ctx)
	fields.values["access"] = this.access.String()
	return fields.target("management")
}

func collectLocalSessionTargetFields(fields *targetFields, conf *configuration.EnvironmentLocalCommon) *targetFields {
	fields.strings("shellCommand", &conf.ShellCommand)
	fields.strings("execCommandPrefix", &conf.ExecCommandPrefix)
	fields.string("directory", &conf.Directory)
	fields.boolean("portForwardingAllowed", &conf.PortForwardingAllowed)
	return fields
}

func nilLocalTargetDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
