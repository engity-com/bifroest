package access

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

// Policy is an immutable, recursive access tree. Its zero value is the concrete
// management default object. Explicit objects never inherit missing properties.
type Policy struct{ root *node }

type node struct {
	constant   bool
	expression string
	render     func(io.Writer, any) error
	children   map[string]*node
}

func Constant(value bool) Policy { return Policy{root: &node{constant: value}} }

func defaultRoot() *node {
	root := &node{children: make(map[string]*node)}
	for _, p := range permissions {
		parts := strings.Split(string(p), ".")
		group := root.children[parts[0]]
		if group == nil {
			group = &node{children: make(map[string]*node)}
			root.children[parts[0]] = group
		}
		group.children[parts[1]] = &node{constant: defaultAllowed(p)}
	}
	return root
}

func (p Policy) effectiveRoot() *node {
	if p.root == nil {
		return defaultRoot()
	}
	return p.root
}

func (p Policy) selected(permission Permission) *node {
	if !permission.Valid() {
		return nil
	}
	n := p.effectiveRoot()
	for _, part := range strings.Split(string(permission), ".") {
		if n.children == nil {
			return n
		}
		n = n.children[part]
		if n == nil {
			return nil
		}
	}
	return n
}

// Allows evaluates only the requested permission, using the verified actor's
// environment context. Neither template errors nor rendered values are exposed.
func (p Policy) Allows(permission Permission, context any) (bool, error) {
	n := p.selected(permission)
	if n == nil {
		return false, nil
	}
	if n.render == nil {
		return n.constant, nil
	}
	var output decisionWriter
	if err := n.render(&output, context); err != nil {
		return false, fmt.Errorf("cannot evaluate management access %s", permission)
	}
	switch strings.TrimSpace(output.String()) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("management access %s must render true or false", permission)
	}
}

func (p Policy) Require(permission Permission, context any) error {
	allowed, err := p.Allows(permission, context)
	if err != nil || !allowed {
		return Denied(permission)
	}
	return nil
}

// MayAllow is a conservative startup diagnostic, never an authorization result.
func (p Policy) MayAllow(permission Permission) bool {
	n := p.selected(permission)
	return n != nil && (n.render != nil || n.constant)
}

// WithConstant returns a copy with one explicit leaf replaced. Unknown catalog
// entries are programmer errors; untrusted operations must instead use Allows.
func (p Policy) WithConstant(permission Permission, value bool) Policy {
	if !permission.Valid() {
		panic("unknown management permission")
	}
	var replace func(*node, []string, string) *node
	replace = func(n *node, parts []string, prefix string) *node {
		if len(parts) == 0 {
			return &node{constant: value}
		}
		children := make(map[string]*node)
		if n != nil && n.children != nil {
			children = maps.Clone(n.children)
		} else if n != nil {
			// Expanding a scalar keeps its meaning for its known descendants.
			for _, candidate := range permissions {
				path := string(candidate)
				if prefix != "" {
					var matched bool
					path, matched = strings.CutPrefix(path, prefix+".")
					if !matched {
						continue
					}
				}
				name, _, _ := strings.Cut(path, ".")
				children[name] = n
			}
		}
		childPrefix := parts[0]
		if prefix != "" {
			childPrefix = prefix + "." + childPrefix
		}
		children[parts[0]] = replace(children[parts[0]], parts[1:], childPrefix)
		return &node{children: children}
	}
	return Policy{root: replace(p.effectiveRoot(), strings.Split(string(permission), "."), "")}
}

func (p Policy) IsEqualTo(other Policy) bool { return p.String() == other.String() }

func (p Policy) String() string {
	encoded, _ := p.MarshalJSON()
	return string(encoded)
}

func (p Policy) MarshalJSON() ([]byte, error) { return json.Marshal(p.effectiveRoot().value()) }
func (p Policy) MarshalYAML() (any, error)    { return p.effectiveRoot().value(), nil }

func (n *node) value() any {
	if n.children != nil {
		result := make(map[string]any, len(n.children))
		for name, child := range n.children {
			result[name] = child.value()
		}
		return result
	}
	if n.render != nil {
		return n.expression
	}
	return n.constant
}

func (p *Policy) UnmarshalYAML(value *yaml.Node) error {
	root, err := parseNode(value, "", make(map[*yaml.Node]bool))
	if err != nil {
		return err
	}
	p.root = root
	return nil
}

func (p *Policy) UnmarshalJSON(value []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(value, &document); err != nil {
		return err
	}
	if len(document.Content) != 1 {
		return fmt.Errorf("invalid management access")
	}
	return p.UnmarshalYAML(document.Content[0])
}

func parseNode(value *yaml.Node, path string, active map[*yaml.Node]bool) (*node, error) {
	if value == nil || active[value] {
		return nil, fmt.Errorf("invalid management access %s", path)
	}
	active[value] = true
	defer delete(active, value)
	if value.Kind == yaml.AliasNode {
		return parseNode(value.Alias, path, active)
	}
	switch {
	case value.Kind == yaml.ScalarNode && value.Tag == "!!bool":
		var constant bool
		if err := value.Decode(&constant); err != nil {
			return nil, err
		}
		return &node{constant: constant}, nil
	case value.Kind == yaml.ScalarNode && value.Tag == "!!str":
		text := strings.TrimSpace(value.Value)
		if text == "true" || text == "false" {
			return &node{constant: text == "true"}, nil
		}
		if !strings.Contains(text, "{{") {
			return nil, fmt.Errorf("management access %s must be a boolean, template or object", path)
		}
		tmpl, err := template.NewTemplate("management access", value.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid management access template %s", path)
		}
		return &node{expression: value.Value, render: tmpl.Execute}, nil
	case value.Kind == yaml.MappingNode:
		if Permission(path).Valid() {
			return nil, fmt.Errorf("management access %s requires a boolean or template", path)
		}
		result := &node{children: make(map[string]*node)}
		for i := 0; i < len(value.Content); i += 2 {
			key := value.Content[i]
			childPath := key.Value
			if path != "" {
				childPath = path + "." + childPath
			}
			known := false
			for _, permission := range permissions {
				if string(permission) == childPath || strings.HasPrefix(string(permission), childPath+".") {
					known = true
					break
				}
			}
			if !known || key.Tag != "!!str" || strings.Contains(key.Value, ".") {
				return nil, fmt.Errorf("unknown management access property %s", childPath)
			}
			if _, duplicate := result.children[key.Value]; duplicate {
				return nil, fmt.Errorf("duplicate management access property %s", childPath)
			}
			child, err := parseNode(value.Content[i+1], childPath, active)
			if err != nil {
				return nil, err
			}
			result.children[key.Value] = child
		}
		return result, nil
	default:
		return nil, fmt.Errorf("management access %s must be a boolean, template or object", path)
	}
}

type decisionWriter struct{ strings.Builder }

func (w *decisionWriter) Write(value []byte) (int, error) {
	if len(value) > 64-w.Len() {
		return 0, fmt.Errorf("management access decision exceeds bound")
	}
	return w.Builder.Write(value)
}

func (w *decisionWriter) WriteString(value string) (int, error) { return w.Write([]byte(value)) }
