package test

import (
	"text/template/parse"

	"github.com/engity-com/bifroest/pkg/template"
)

// Resource admission, NOT a second renderer: admitted templates are always run
// by the existing production implementation. Loops, recursion, function-valued
// data, formatting widths and allocating Sprig functions are not yet supported.
func admitTemplate(source string) error {
	return admitTemplateFields(source, func(fields []string) error {
		// Whole native wrappers format private implementation state, including
		// pointers. Only their data getters belong to the controlled vocabulary.
		if fields[0] == "authorization" && (len(fields) == 1 || (len(fields) == 2 && (fields[1] == "token" || fields[1] == "idToken" || fields[1] == "userInfo"))) {
			return invalid("whole authorization wrappers are outside the bounded offline slice")
		}
		// Native OIDC metadata retains time.Time. Its methods (notably Local)
		// must not expose host timezone state or additional Go capabilities.
		if len(fields) > 3 && fields[0] == "authorization" && ((fields[1] == "token" && fields[2] == "expiry") || (fields[1] == "idToken" && (fields[2] == "expiry" || fields[2] == "issuedAt"))) {
			return invalid("OIDC time metadata methods are outside the bounded offline slice")
		}
		return nil
	})
}

func admitTemplateFields(source string, field func([]string) error) error {
	if len(source) > maxString {
		return invalid("template source limit exceeded")
	}
	tmpl, err := template.NewTemplate("offline", source)
	if err != nil {
		return invalid("invalid policy template")
	}
	if len(tmpl.Templates()) != 1 {
		return invalid("named templates are not supported in the bounded offline slice")
	}
	remaining := 128
	var visit func(parse.Node, int) error
	visit = func(node parse.Node, depth int) error {
		if node == nil {
			return nil
		}
		remaining--
		if remaining < 0 || depth > maxDepth {
			return invalid("template structure limit exceeded")
		}
		child := func(n parse.Node) error { return visit(n, depth+1) }
		switch n := node.(type) {
		case *parse.ListNode:
			if n == nil {
				return nil
			}
			for _, item := range n.Nodes {
				if err := child(item); err != nil {
					return err
				}
			}
		case *parse.ActionNode:
			return child(n.Pipe)
		case *parse.PipeNode:
			for _, command := range n.Cmds {
				if err := child(command); err != nil {
					return err
				}
			}
		case *parse.CommandNode:
			for _, arg := range n.Args {
				if err := child(arg); err != nil {
					return err
				}
			}
		case *parse.IfNode:
			if err := child(n.Pipe); err != nil {
				return err
			}
			if err := child(n.List); err != nil {
				return err
			}
			return child(n.ElseList)
		case *parse.IdentifierNode:
			switch n.Ident {
			case "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not", "len":
			default:
				return invalid("template function is outside the bounded offline slice")
			}
		case *parse.FieldNode:
			if field != nil {
				return field(n.Ident)
			}
		case *parse.TextNode, *parse.StringNode, *parse.BoolNode, *parse.NumberNode, *parse.NilNode:
		default:
			return invalid("template construct is outside the bounded offline slice")
		}
		return nil
	}
	return visit(tmpl.Tree.Root, 0)
}
