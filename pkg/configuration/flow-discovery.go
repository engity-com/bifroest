package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/net"
)

// HttpDiscovery returns only explicitly published slugs, in configuration order.
// The HTTP endpoint must enforce its domain allowlist before calling this method.
// Name/slug requirements and authorization are still checked when a link is used.
func (this Flows) HttpDiscovery(host string) ([]string, error) {
	host, err := net.CanonicalHttpHost(host)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	seen := make(map[string]FlowName)
	for _, flow := range this {
		if !flow.Http.IsEnabled() || flow.DiscoverAsSlug == "" || !flow.Requirement.Http.MatchesHost(host) {
			continue
		}
		if err := net.ValidateHttpSlug(flow.DiscoverAsSlug); err != nil {
			return nil, fmt.Errorf("flow %q has an invalid discovery slug: %w", flow.Name, err)
		}
		if previous, exists := seen[flow.DiscoverAsSlug]; exists {
			return nil, fmt.Errorf("flows %q and %q publish the same slug %q on host %q", previous, flow.Name, flow.DiscoverAsSlug, host)
		}
		seen[flow.DiscoverAsSlug] = flow.Name
		result = append(result, flow.DiscoverAsSlug)
	}
	return result, nil
}

// ValidateHttpDiscovery checks collisions against the finite set of configured
// endpoint domains, rather than guessing whether two arbitrary regexes overlap.
func (this Flows) ValidateHttpDiscovery(domains []string) error {
	for _, domain := range domains {
		if _, err := this.HttpDiscovery(domain); err != nil {
			return err
		}
	}
	return nil
}

// ResolveHttpSlug returns a fixed published assignment, not authorization. A
// selected flow must still pass every requirement and must not fall through on
// failure. Empty/non-published slugs retain normal configuration-order matching.
func (this Flows) ResolveHttpSlug(host, slug string) (FlowName, bool, error) {
	host, err := net.CanonicalHttpHost(host)
	if err != nil {
		return "", false, err
	}
	if err := net.ValidateHttpSlug(slug); err != nil {
		return "", false, err
	}
	if slug == "" {
		return "", false, nil
	}
	var selected FlowName
	found := false
	for _, flow := range this {
		if !flow.Http.IsEnabled() || flow.DiscoverAsSlug != slug || !flow.Requirement.Http.MatchesHost(host) {
			continue
		}
		if found {
			return "", false, fmt.Errorf("multiple flows publish slug %q on host %q", slug, host)
		}
		selected, found = flow.Name, true
	}
	return selected, found, nil
}
