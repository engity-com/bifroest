package format

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func WriteSettings(output io.Writer, selected Format, settings map[string]any) error {
	if selected != Text {
		return WriteStructured(output, selected, settings)
	}
	var fields []Field
	if err := appendSettingsFields(&fields, "", settings); err != nil {
		return err
	}
	return WriteDetail(output, selected, fields, settings)
}

func appendSettingsFields(fields *[]Field, prefix string, settings map[string]any) error {
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
			if err := appendSettingsFields(fields, path, nested); err != nil {
				return err
			}
			continue
		}
		if entries, ok := settings[key].([]any); ok && len(entries) != 0 {
			for index, entry := range entries {
				itemPath := fmt.Sprintf("%s[%d]", path, index)
				if mapping, ok := entry.(map[string]any); ok {
					if err := appendSettingsFields(fields, itemPath, mapping); err != nil {
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
