package configuration

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
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
	FeatureFlags() []string
}

var (
	typeToSessionFactory = make(map[string]SessionVFactory)
	sessionVs            []SessionV
)

type SessionVFactory func() SessionV

func RegisterSessionV(factory SessionVFactory) SessionVFactory {
	pt := factory()
	ts := pt.Types()
	if len(ts) == 0 {
		panic(fmt.Errorf("the instance does not provide any type"))
	}
	for _, t := range ts {
		typeToSessionFactory[strings.ToLower(t)] = factory
	}
	sessionVs = append(sessionVs, pt)
	return factory
}

func (this *Session) SetDefaults() error {
	*this = Session{&SessionFs{}}
	if err := this.V.SetDefaults(); err != nil {
		return err
	}
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

	factory, ok := typeToSessionFactory[strings.ToLower(typeBuf.Type)]
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

func GetSupportedSessionFeatureFlags() []string {
	var result []string
	for _, v := range sessionVs {
		result = append(result, v.FeatureFlags()...)
	}
	sort.Strings(result)
	return result
}
