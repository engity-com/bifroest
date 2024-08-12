package configuration

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"gopkg.in/yaml.v3"
	"reflect"
	"strings"
)

var (
	// DefaultSessionIdleTimeout is the default setting for Session.IdleTimeout.
	DefaultSessionIdleTimeout = common.MustNewDuration("30m")

	// DefaultSessionMaxTimeout is the default setting for Session.MaxTimeout.
	DefaultSessionMaxTimeout = common.MustNewDuration("0")

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
}

func (this *Session) SetDefaults() error {
	*this = Session{&SessionSimple{}}
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

	switch strings.ToLower(typeBuf.Type) {
	case "", "disabled", "simple", "no", "false", "off":
		this.V = &SessionSimple{}
	case "fs", "file_system":
		this.V = &SessionFs{}
	default:
		return reportYamlRelatedErrf(node, "[type] illegal type: %q", typeBuf.Type)
	}

	if err := node.Decode(this.V); err != nil {
		return reportYamlRelatedErr(node, err)
	}

	return this.Trim()
}

func (this *Session) MarshalYAML() (any, error) {
	typeBuf := struct {
		SessionV `yaml:",inline"`
		Type     string `yaml:"type"`
	}{
		SessionV: this.V,
	}

	switch typeBuf.SessionV.(type) {
	case *SessionSimple:
		typeBuf.Type = "disabled"
	case *SessionFs:
		typeBuf.Type = "fs"
	default:
		return nil, fmt.Errorf("[type] illegal type: %v", reflect.TypeOf(typeBuf.SessionV))
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
