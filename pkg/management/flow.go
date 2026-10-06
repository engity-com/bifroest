package management

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// ConfigurationSource is invoked only when a command actually needs the
// configuration. A remote source rejects local configuration file paths.
type ConfigurationSource func(path string) (*configuration.Configuration, error)

type FlowSummary struct {
	Name          configuration.FlowName     `json:"name" yaml:"name"`
	Auditlog      configuration.AuditlogName `json:"auditlog" yaml:"auditlog"`
	Authorization string                     `json:"authorization" yaml:"authorization"`
	Environment   string                     `json:"environment" yaml:"environment"`
}

func RegisterFlowCommands(app *kingpin.Application, source ConfigurationSource, output io.Writer, includeCredentials, local bool) {
	parent := app.Command("flow", "Inspect configured flows.")
	var format string
	formats := []string{"table", "json", "yaml"}
	if !local {
		formats = append(formats, "cbor")
	}
	parent.Flag("format", "Display as a table/list, JSON, or YAML.").Default("table").EnumVar(&format, formats...)
	var configPath string
	if local {
		parent.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&configPath)
	}
	parent.Command("ls", "List configured flows.").Action(func(*kingpin.ParseContext) error {
		conf, err := source(configPath)
		if err != nil {
			return err
		}
		return ListFlows(output, Format(format), conf)
	})
	var name configuration.FlowName
	parent.Command("show", "Show the settings of one flow.").Action(func(*kingpin.ParseContext) error {
		conf, err := source(configPath)
		if err != nil {
			return err
		}
		return ShowFlow(output, Format(format), conf, name, includeCredentials)
	}).Arg("name", "Name of the flow.").Required().SetValue(&name)
}

func ListFlows(output io.Writer, format Format, conf *configuration.Configuration) error {
	if conf == nil {
		return fmt.Errorf("missing configuration")
	}
	entries := make([]FlowSummary, 0, len(conf.Flows))
	for _, flow := range conf.Flows {
		authorization, environment := "", ""
		if flow.Authorization.V != nil {
			authorization = flow.Authorization.V.Types()[0]
		}
		if flow.Environment.V != nil {
			environment = flow.Environment.V.Types()[0]
		}
		entries = append(entries, FlowSummary{flow.Name, flow.Auditlog, authorization, environment})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return WriteFlowList(output, format, entries)
}

func WriteFlowList(output io.Writer, format Format, entries []FlowSummary) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.Name.String(), entry.Auditlog.String(), entry.Authorization, entry.Environment})
	}
	return WriteList(output, format, []string{"NAME", "AUDITLOG", "AUTHORIZATION", "ENVIRONMENT"}, rows, entries)
}

func ShowFlow(output io.Writer, format Format, conf *configuration.Configuration, name configuration.FlowName, includeCredentials bool) error {
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
			redactFlowSettings(settings)
		}
		return WriteFlowSettings(output, format, settings)
	}
	return fmt.Errorf("flow %q does not exist", name)
}

func WriteFlowSettings(output io.Writer, format Format, settings map[string]any) error {
	if format != FormatTable {
		return writeStructured(output, format, settings)
	}
	var fields []Field
	if err := appendFlowFields(&fields, "", settings); err != nil {
		return err
	}
	return WriteDetail(output, format, fields, settings)
}

func appendFlowFields(fields *[]Field, prefix string, settings map[string]any) error {
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if nested, ok := settings[key].(map[string]any); ok {
			if err := appendFlowFields(fields, path, nested); err != nil {
				return err
			}
			continue
		}
		if entries, ok := settings[key].([]any); ok && len(entries) != 0 {
			for index, entry := range entries {
				itemPath := fmt.Sprintf("%s[%d]", path, index)
				if mapping, ok := entry.(map[string]any); ok {
					if err := appendFlowFields(fields, itemPath, mapping); err != nil {
						return err
					}
					continue
				}
				encoded, err := yaml.Marshal(entry)
				if err != nil {
					return err
				}
				*fields = append(*fields, Field{Name: itemPath, Value: strings.TrimSpace(string(encoded))})
			}
			continue
		}
		value, err := yaml.Marshal(settings[key])
		if err != nil {
			return err
		}
		*fields = append(*fields, Field{Name: path, Value: strings.TrimSpace(string(value))})
	}
	return nil
}

func redactFlowSettings(settings map[string]any) {
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
			redactFlowSettings(nested)
		case []any:
			for _, entry := range nested {
				if mapping, ok := entry.(map[string]any); ok {
					redactFlowSettings(mapping)
				}
			}
		}
	}
}
