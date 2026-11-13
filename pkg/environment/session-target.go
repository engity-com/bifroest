package environment

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

// SessionTargetResolver describes the effective, server-selected environment.
// It must not provision resources, acquire credentials or open target transports.
// The caller supplies a candidate-specific template context (including session.id).
type SessionTargetResolver interface {
	ResolveSessionTarget(Context) (session.Target, error)
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

// targetFields never propagates template error text: rendered target fields may
// include operator-controlled sensitive values. Only the final digest persists.
type targetFields struct {
	ctx    Context
	values map[string]string
	err    error
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
		this.err = fmt.Errorf("cannot resolve session target field %s", name)
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
		this.err = fmt.Errorf("cannot resolve session target field %s", name)
		return
	}
	if rendered == nil {
		rendered = []string{}
	}
	raw, err := json.Marshal(rendered)
	if err != nil {
		this.err = fmt.Errorf("cannot encode session target field %s", name)
		return
	}
	this.values[name] = string(raw)
}
func (this *targetFields) boolean(name string, value *template.Bool) {
	if this.err != nil {
		return
	}
	rendered, err := value.Render(this.ctx)
	if err != nil {
		this.err = fmt.Errorf("cannot resolve session target field %s", name)
		return
	}
	this.values[name] = strconv.FormatBool(rendered)
}
func (this *targetFields) target(kind string) (session.Target, error) {
	if this.err != nil {
		return "", this.err
	}
	if err := this.ctx.Context().Err(); err != nil {
		return "", err
	}
	return session.NewTarget(kind, this.values)
}

func (this *DummyRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	return newTargetFields(ctx).target("dummy")
}
func (this *ManagementRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	fields := newTargetFields(ctx)
	fields.values["includingCredentials"] = strconv.FormatBool(this.includingCredentials)
	fields.values["allowArtifactTransfer"] = strconv.FormatBool(this.allowArtifactTransfer)
	return fields.target("management")
}

func localSessionTargetFields(ctx Context, conf *configuration.EnvironmentLocalCommon) *targetFields {
	fields := newTargetFields(ctx)
	fields.strings("shellCommand", &conf.ShellCommand)
	fields.strings("execCommandPrefix", &conf.ExecCommandPrefix)
	fields.string("directory", &conf.Directory)
	fields.boolean("portForwardingAllowed", &conf.PortForwardingAllowed)
	return fields
}
