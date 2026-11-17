package service

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"net/http"
	"net/url"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func managementPathName(value string, maximum int, underscore bool) bool {
	if value == "" || len(value) > maximum || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || underscore && r == '_' {
			continue
		}
		return false
	}
	return true
}

// A SPA suffix must name a configured management flow eligible for the ORIGINAL
// access scope. A terminal-only root must never turn /Unknown into root login.
// This is public routing eligibility, not authentication or a replacement for
// the facade's selection/published-link checks on every login.
func (this *webService) configuredManagementEntry(host, slug, expected string) bool {
	for _, flow := range this.service.Configuration.Flows {
		if slug != "" && flow.DiscoverAsSlug == slug && flow.Name.String() != expected {
			return false
		}
	}
	for _, flow := range this.service.Configuration.Flows {
		if flow.Name.String() != expected {
			continue
		}
		_, management := flow.Environment.V.(*configuration.EnvironmentManagement)
		return management && flow.Http.IsEnabled() && flow.Requirement.Http.MatchesHost(host) && flow.Requirement.Http.MatchesSlug(slug) && (flow.Http.RequestUserEnabled() || flow.Requirement.MatchesHttp("", host, slug))
	}
	return false
}
func managementPathID(value string) bool {
	_, err := uuidtext.Parse(value)
	return err == nil
}

// Recognize only the SPA's explicit public route grammar. No path is a command,
// grant or artifact read; APIs retain their original namespace and POST fields.
func validManagementLocation(value *url.URL, slug string) bool {
	if value == nil || value.Opaque != "" || value.Fragment != "" || value.ForceQuery || len(value.RawQuery) > 512 || strings.HasSuffix(value.Path, "/") || len(value.Path) > 2048 || strings.ContainsAny(value.EscapedPath(), "%\\") || (value.RawPath != "" && value.RawPath != value.Path) || bnet.ValidateHttpSlug(slug) != nil {
		return false
	}
	prefix := "/"
	if slug != "" {
		prefix += slug + "/"
	}
	if !strings.HasPrefix(value.Path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value.Path, prefix), "/")
	if !managementPathName(parts[0], 255, false) {
		return false
	}
	parts = parts[1:]
	section := ""
	if len(parts) > 0 {
		section = parts[0]
		parts = parts[1:]
	}
	collection := section
	sourceBound, flowInPath, detail := false, false, false
	switch section {
	case "", "version":
		if len(parts) != 0 {
			return false
		}
	case "sessions", "recordings":
		if len(parts) > 2 {
			return false
		}
		if len(parts) > 0 && !managementPathName(parts[0], 255, false) {
			return false
		}
		if len(parts) > 1 && !managementPathID(parts[1]) {
			return false
		}
		flowInPath, detail = len(parts) > 0, len(parts) > 1
	case "auditlogs":
		if len(parts) > 3 {
			return false
		}
		if len(parts) > 0 && !managementPathName(parts[0], 128, true) {
			return false
		}
		if len(parts) > 1 && !managementPathName(parts[1], 255, false) {
			return false
		}
		if len(parts) > 2 && !managementPathID(parts[2]) {
			return false
		}
		sourceBound, flowInPath, detail = len(parts) > 0, len(parts) > 1, len(parts) > 2
		if len(parts) > 1 && (parts[1] == "events" || parts[1] == "recordings") {
			flowInPath = false
			if parts[1] == "recordings" {
				collection = "recordings"
			}
		}
	default:
		return false
	}
	query, err := url.ParseQuery(value.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 {
			return false
		}
		if key == "auditlog" && section == "recordings" && !sourceBound && managementPathName(values[0], 128, true) {
			continue
		}
		if key == "recording" && collection == "recordings" && !detail && managementPathID(values[0]) {
			continue
		}
		if key == "event" && collection == "auditlogs" && sourceBound && !detail && managementPathID(values[0]) {
			continue
		}
		if key == "flow" && (collection == "auditlogs" || collection == "recordings") && !flowInPath && managementPathName(values[0], 255, false) {
			continue
		}
		if key == "sessionId" && (collection == "auditlogs" || collection == "recordings") && managementPathID(values[0]) && values[0] != "00000000-0000-0000-0000-000000000000" {
			continue
		}
		return false
	}
	return true
}

func (this *webService) describeSlug(r *http.Request) (string, error) {
	legacy := ""
	legacyAvailable := false
	if slug, err := bnet.HttpSlugFromURL(r.URL); err == nil && r.URL.RawQuery == "" && !r.URL.ForceQuery {
		scope, err := requestWebScope(r, slug)
		if err != nil {
			return "", err
		}
		description, err := this.service.authorizerDiscovery.DescribeHttpLogin(scope.selection().Host, slug)
		if err != nil {
			return "", err
		}
		if description.Available {
			legacy, legacyAvailable = slug, true
			// Explicit published links keep their exact original scope. Broad
			// alias regexes must not swallow a configured management suffix.
			for _, flow := range this.service.Configuration.Flows {
				if slug != "" && flow.DiscoverAsSlug == slug {
					return slug, nil
				}
			}
		}
	}
	if !strings.HasPrefix(r.URL.Path, "/") {
		return "", fmt.Errorf("invalid management path")
	}
	parts := strings.Split(r.URL.Path[1:], "/")
	selected := ""
	found := false
	for count := 0; count <= 2 && count < len(parts); count++ {
		slug := strings.Join(parts[:count], "/")
		if !validManagementLocation(r.URL, slug) {
			continue
		}
		scope, err := requestWebScope(r, slug)
		if err != nil {
			continue
		}
		if !this.configuredManagementEntry(scope.selection().Host, slug, parts[count]) {
			continue
		}
		description, err := this.service.authorizerDiscovery.DescribeHttpLogin(scope.selection().Host, slug)
		if err != nil {
			return "", err
		}
		if !description.Available {
			continue
		}
		if found && selected != slug {
			return "", fmt.Errorf("ambiguous management path")
		}
		selected = slug
		found = true
	}
	if found {
		return selected, nil
	}
	if legacyAvailable {
		return legacy, nil
	}
	// Root directories and denied/nonexistent legacy links retain their existing
	// discovery and error behavior, but never accept arbitrary query parameters.
	if r.URL.RawQuery == "" && !r.URL.ForceQuery {
		return bnet.HttpSlugFromURL(r.URL)
	}
	return "", fmt.Errorf("invalid management location")
}
