package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type HttpMode uint8

const (
	HttpDisabled HttpMode = iota
	HttpEnabled
	HttpAcmeTlsAlpnOnly
)

func (this HttpMode) Validate() error {
	switch this {
	case HttpDisabled, HttpEnabled, HttpAcmeTlsAlpnOnly:
		return nil
	default:
		return fmt.Errorf("must be false, true or acmeTlsAlpnOnly")
	}
}

func (this *HttpMode) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!bool" {
			var enabled bool
			if err := node.Decode(&enabled); err != nil {
				return err
			}
			*this = HttpDisabled
			if enabled {
				*this = HttpEnabled
			}
			return nil
		}
		if node.Tag == "!!str" && node.Value == "acmeTlsAlpnOnly" {
			*this = HttpAcmeTlsAlpnOnly
			return nil
		}
	}
	return fmt.Errorf("must be false, true or acmeTlsAlpnOnly")
}

func (this HttpMode) MarshalYAML() (any, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	if this == HttpAcmeTlsAlpnOnly {
		return "acmeTlsAlpnOnly", nil
	}
	return this == HttpEnabled, nil
}
