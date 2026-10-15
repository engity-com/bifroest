package flow

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func ListFlows(output io.Writer, selected cliformat.Format, conf *configuration.Configuration) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	entries := make([]model.FlowSummary, 0, len(conf.Flows))
	for _, flow := range conf.Flows {
		authorization, environment := "", ""
		if flow.Authorization.V != nil {
			authorization = flow.Authorization.V.Types()[0]
		}
		if flow.Environment.V != nil {
			environment = flow.Environment.V.Types()[0]
		}
		entries = append(entries, model.FlowSummary{
			Name: flow.Name, Auditlog: flow.Auditlog,
			Authorization: authorization, Environment: environment,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return cliformat.WriteFlowList(output, selected, entries)
}

func ShowFlow(output io.Writer, selected cliformat.Format, conf *configuration.Configuration, name configuration.FlowName, includeCredentials bool) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	for _, flow := range conf.Flows {
		if flow.Name != name {
			continue
		}
		encoded, err := yaml.Marshal(map[string]any{
			"name": flow.Name, "auditlog": flow.Auditlog,
			"requirement":   &flow.Requirement,
			"authorization": &flow.Authorization,
			"environment":   &flow.Environment,
		})
		if err != nil {
			return fmt.Errorf("cannot encode flow %q: %w", name, err)
		}
		var settings map[string]any
		if err := yaml.Unmarshal(encoded, &settings); err != nil {
			return err
		}
		if !includeCredentials {
			publicEnvironment := publicFlowEnvironmentSettings(flow.Environment.V, settings)
			RedactSettings(settings)
			if environment, ok := settings["environment"].(map[string]any); ok {
				for key, value := range publicEnvironment {
					environment[key] = value
				}
			}
		}
		return cliformat.WriteSettings(output, selected, settings)
	}
	return fmt.Errorf("flow %q does not exist", name)
}

// Only fixed enum values are public environment metadata. Image references
// remain private because even a syntactically valid name may contain secrets.
func publicFlowEnvironmentSettings(configured configuration.EnvironmentV, settings map[string]any) map[string]string {
	switch configured.(type) {
	case *configuration.EnvironmentDocker, *configuration.EnvironmentKubernetes:
	default:
		return nil
	}
	environment, ok := settings["environment"].(map[string]any)
	if !ok {
		return nil
	}
	result := map[string]string{}
	if policy, ok := environment["imagePullPolicy"].(string); ok {
		switch policy {
		case "ifAbsent", "always", "never":
			result["imagePullPolicy"] = policy
		}
	}
	return result
}

func RedactSettings(settings map[string]any) {
	for key, value := range settings {
		lower := strings.ToLower(key)
		if lower == "variables" || strings.Contains(lower, "password") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "credential") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "private") || strings.Contains(lower, "identityfile") ||
			lower == "accesskeyid" {
			settings[key] = "***redacted***"
			continue
		}
		switch nested := value.(type) {
		case map[string]any:
			RedactSettings(nested)
		case []any:
			redactFlowEntries(nested)
		case string:
			// Arbitrary configuration strings (including commands, URLs and
			// templates) can contain credentials without a secret-looking key.
			// Only structural names are safe to show by default.
			if lower != "name" && lower != "type" && lower != "auditlog" {
				settings[key] = "***redacted***"
			}
		}
	}
}

func redactFlowEntries(entries []any) {
	for index, entry := range entries {
		switch value := entry.(type) {
		case map[string]any:
			RedactSettings(value)
		case []any:
			redactFlowEntries(value)
		case string:
			entries[index] = "***redacted***"
		}
	}
}
