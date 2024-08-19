package configuration

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"gopkg.in/yaml.v3"
	"strings"
	"time"
)

var (
	// DefaultSessionIdleTimeout is the default setting for Session.IdleTimeout.
	DefaultSessionIdleTimeout = common.DurationOf(30 * time.Minute)

	// DefaultSessionMaxTimeout is the default setting for Session.MaxTimeout.
	DefaultSessionMaxTimeout = common.DurationOf(0)

	// DefaultSessionMaxConnections is the default setting for Session.MaxConnections.
	DefaultSessionMaxConnections uint16 = 10
)

type Session struct {
	V SessionV
}

type SessionV interface {
	defaulter
	trimmer
	validator
	equaler
	Types() []string
}

var (
	typeToSessionFactory map[string]SessionVFactory
)

type SessionVFactory func() SessionV

func RegisterSessionV(factory SessionVFactory) SessionVFactory {
	pt := factory()
	ts := pt.Types()
	if len(ts) == 0 {
		panic(fmt.Errorf("the instance does not provide any type"))
	}
	for _, t := range ts {
		typeToSessionFactory[t] = factory
	}
	return factory
}

func (this *Session) SetDefaults() error {
	*this = Session{}
	return nil
}

func (this *Session) Trim() error {
	if this.V != nil {
		if err := this.V.Trim(); err != nil {
			return err
		}
	}
	return this.Validate()
}

func (this *Session) Validate() error {
	if v := this.V; v != nil {
		return v.Validate()
	}
	return fmt.Errorf("required but absent")
}

func (this *Session) UnmarshalYAML(node *yaml.Node) error {
	var typeBuf struct {
		Type string `yaml:"type"`
	}

	if err := node.Decode(&typeBuf); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if err := this.SetDefaults(); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	if typeBuf.Type == "" {
		return reportYamlRelatedErrf(node, "[type] required but absent")
	}

	factory, ok := typeToEnvironmentFactory[typeBuf.Type]
	if !ok {
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	this.V = factory()
	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Session) MarshalYAML() (any, error) {
	typeBuf := struct {
		SessionV `yaml:",inline"`
		Type     string `yaml:"type"`
	}{}

	if this.V != nil {
		typeBuf.Type = this.V.Types()[0]
		typeBuf.SessionV = this.V
	}

	return typeBuf, nil
}

func (this Session) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Session:
		return this.isEqualTo(&v)
	case *Session:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Session) isEqualTo(other *Session) bool {
	if other.V == nil {
		return this.V == nil
	}
	return this.V.IsEqualTo(other.V)
}

func GetSupportedSessionVs() []string {
	result := make([]string, len(typeToSessionFactory))
	var i int
	for k := range typeToSessionFactory {
		result[i] = strings.Clone(k)
	}
	return result
}
