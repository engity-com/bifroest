package configuration

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// effectiveHttpFields includes YAML merge fields, so aliases/merges cannot hide
// unknown fields or null values for which yaml skips UnmarshalYAML methods.
func effectiveHttpFields(node *yaml.Node) (map[string]yaml.Node, error) {
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" {
		return nil, reportYamlRelatedErrf(node, "expected a mapping")
	}
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return nil, err
	}
	for key, value := range fields {
		if value.Kind == yaml.AliasNode && value.Alias != nil {
			fields[key] = *value.Alias
		}
	}
	return fields, nil
}

func decodeHttpFields(node *yaml.Node, target any, known map[string]string) error {
	fields, err := effectiveHttpFields(node)
	if err != nil {
		return err
	}
	for name, value := range fields {
		specification, exists := known[name]
		if !exists {
			return reportYamlRelatedErrf(&value, "field %s not found", name)
		}
		// Sequence specifications additionally describe their item type. yaml.v3
		// otherwise silently removes null items from some typed slices.
		tag, itemTag, _ := strings.Cut(specification, "/")
		if value.Tag != tag {
			// Never include the rejected scalar: a pasted private key must not
			// become part of a configuration error or log message.
			return reportYamlRelatedErr(&value, fmt.Errorf("[%s] must have YAML type %s", name, tag))
		}
		if itemTag != "" {
			for index, item := range value.Content {
				if item.Kind == yaml.AliasNode && item.Alias != nil {
					item = item.Alias
				}
				if item.Tag != itemTag {
					return reportYamlRelatedErrf(item, "[%s][%d] must have YAML type %s", name, index, itemTag)
				}
			}
		}
	}
	return decodeConfigurationFields(node, target)
}
