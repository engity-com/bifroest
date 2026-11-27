package configuration

import (
	"fmt"
	"slices"
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
		if !slices.Contains(strings.Split(tag, "|"), value.Tag) {
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

// The overridden field must be omitted by value's raw YAML representation.
func marshalWithYAMLField(value any, name string, field any) (any, error) {
	var result, encoded yaml.Node
	if err := result.Encode(value); err != nil {
		return nil, err
	}
	if err := encoded.Encode(field); err != nil {
		return nil, err
	}
	result.Content = append(result.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, &encoded)
	return &result, nil
}
