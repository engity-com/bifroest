package configuration

import (
	"fmt"
	stdnet "net"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
)

// HttpDomains is a finite allowlist, never a wildcard or a source of requesting
// names. Ports belong to listener addresses, not to this list.
type HttpDomains []string

func (this HttpDomains) Canonical() ([]string, error) {
	result := make([]string, len(this))
	seen := make(map[string]int, len(this))
	for index, domain := range this {
		if _, _, err := stdnet.SplitHostPort(domain); err == nil {
			return nil, fmt.Errorf("[%d] domain must not contain a port", index)
		}
		host, err := net.CanonicalHttpHost(domain)
		if err != nil {
			return nil, fmt.Errorf("[%d] invalid HTTP domain: %w", index, err)
		}
		if previous, exists := seen[host]; exists {
			return nil, fmt.Errorf("[%d] duplicates domain [%d]", index, previous)
		}
		seen[host] = index
		result[index] = host
	}
	return result, nil
}

func (this *HttpDomains) Trim() error {
	canonical, err := this.Canonical()
	if err != nil {
		return err
	}
	*this = canonical
	return nil
}

func (this HttpDomains) Validate() error {
	_, err := this.Canonical()
	return err
}

func (this *HttpDomains) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("domains must be a sequence")
	}
	for _, entry := range node.Content {
		if entry.Kind == yaml.AliasNode && entry.Alias != nil {
			entry = entry.Alias
		}
		if entry.Tag != "!!str" {
			return reportYamlRelatedErrf(entry, "domain must be a string")
		}
	}
	type raw HttpDomains
	if err := node.Decode((*raw)(this)); err != nil {
		return err
	}
	return this.Trim()
}

func (this HttpDomains) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case HttpDomains:
		return slices.Equal(this, value)
	case *HttpDomains:
		return value != nil && slices.Equal(this, *value)
	default:
		return false
	}
}

// AllowsHost checks the same canonical host representation used by flow
// selection. It is not a substitute for SNI/Origin checks at the HTTP boundary.
func (this HttpDomains) AllowsHost(authority string) (bool, error) {
	host, err := net.CanonicalHttpHost(authority)
	if err != nil {
		return false, err
	}
	domains, err := this.Canonical()
	return err == nil && slices.Contains(domains, host), err
}
