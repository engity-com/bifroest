package template

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestExecutePatched(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		output  string
		data    any
		options []string
		ok      bool
	}{
		{"invalid-nil-root-root-to-no-value", "{{.}}", "<no value>", nil, []string{}, true},
		{"invalid-nil-at-root-to-no-value", "{{.x}}", "<no value>", nil, []string{}, true},
		{"invalid-absent-to-no-value", "{{.x}}", "<no value>", map[string]any{}, []string{}, true},
		{"invalid-nil-to-no-value", "{{.x}}", "<no value>", map[string]any{"x": nil}, []string{}, true},
		{"invalid-some-to-value", "{{.x}}", "some", map[string]any{"x": "some"}, []string{}, true},

		{"invalid-nil-root-to-empty", "{{.}}", "", nil, []string{"invalid=empty"}, true},
		{"invalid-nil-at-root-to-empty", "{{.x}}", "", nil, []string{"invalid=empty"}, true},
		{"invalid-absent-to-empty", "{{.x}}", "", map[string]any{}, []string{"invalid=empty"}, true},
		{"invalid-nil-to-empty", "{{.x}}", "", map[string]any{"x": nil}, []string{"invalid=empty"}, true},
		{"invalid-some-empty-to-value", "{{.x}}", "some", map[string]any{"x": "some"}, []string{"invalid=empty"}, true},

		{"invalid-nil-root-to-nil", "{{.}}", "<nil>", nil, []string{"invalid=nil"}, true},
		{"invalid-nil-at-root-to-nil", "{{.x}}", "<nil>", nil, []string{"invalid=nil"}, true},
		{"invalid-absent-to-nil", "{{.x}}", "<nil>", map[string]any{}, []string{"invalid=nil"}, true},
		{"invalid-nil-to-nil", "{{.x}}", "<nil>", map[string]any{"x": nil}, []string{"invalid=nil"}, true},
		{"invalid-some-nil-to-value", "{{.x}}", "some", map[string]any{"x": "some"}, []string{"invalid=nil"}, true},

		{"nil-nil-to-nil", "{{.x}}", "<nil>", map[string]any{"x": nil}, []string{"invalid=nil"}, true},
		{"nil-some-nil-to-value", "{{.x}}", "some", map[string]any{"x": "some"}, []string{"invalid=nil"}, true},

		{"nil-nil-to-empty", "{{.x}}", "", map[string]any{"x": nil}, []string{"invalid=nil", "nil=empty"}, true},
		{"nil-some-empty-to-value", "{{.x}}", "some", map[string]any{"x": "some"}, []string{"invalid=nil", "nil=empty"}, true},

		{"provider0-A-exists", "{{.A}}", "vA", provider0{}, nil, true},
		{"provider0-b-exists", "{{.b}}", "vb", provider0{}, nil, true},
		{"provider0-c-absent", "{{.c}}", `template: provider0-c-absent:1:2: executing "provider0-c-absent" at <.c>: can't evaluate field c in type template.provider0`, provider0{}, nil, false},
		{"provider0-D-regular", "{{.D}}", "vD", provider0{"vD"}, nil, true},

		{"providerWithEmbedded-A-exists", "{{.A}}", "vA", providerWithEmbedded{}, nil, true},
		{"providerWithEmbedded-b-exists", "{{.b}}", "vb", providerWithEmbedded{}, nil, true},
		{"providerWithEmbedded-c-exists", "{{.c}}", "vc", providerWithEmbedded{}, nil, true},
		{"providerWithEmbedded-d-absent", "{{.d}}", `template: providerWithEmbedded-d-absent:1:2: executing "providerWithEmbedded-d-absent" at <.d>: can't evaluate field d in type template.providerWithEmbedded`, providerWithEmbedded{}, nil, false},
		{"providerWithEmbedded-D-regular", "{{.D}}", "vD", providerWithEmbedded{ProviderEmbedded{"vD"}}, nil, true},

		{"providerWithPrivateEmbedded-A-exists", "{{.A}}", "vA", providerWithPrivateEmbedded{}, nil, true},
		{"providerWithPrivateEmbedded-b-exists", "{{.b}}", "vb", providerWithPrivateEmbedded{}, nil, true},
		{"providerWithPrivateEmbedded-c-absent", "{{.c}}", `template: providerWithPrivateEmbedded-c-absent:1:2: executing "providerWithPrivateEmbedded-c-absent" at <.c>: can't evaluate field c in type template.providerWithPrivateEmbedded`, providerWithPrivateEmbedded{}, nil, false},
		{"providerWithPrivateEmbedded-d-absent", "{{.d}}", `template: providerWithPrivateEmbedded-d-absent:1:2: executing "providerWithPrivateEmbedded-d-absent" at <.d>: can't evaluate field d in type template.providerWithPrivateEmbedded`, providerWithPrivateEmbedded{}, nil, false},

		{"sub-provider0-A-exists", "{{.p.A}}", "vA", map[string]any{"p": provider0{}}, nil, true},
		{"sub-provider0-b-exists", "{{.p.b}}", "vb", map[string]any{"p": provider0{}}, nil, true},
		{"sub-provider0-c-absent", "{{.p.c}}", `template: sub-provider0-c-absent:1:4: executing "sub-provider0-c-absent" at <.p.c>: can't evaluate field c in type interface {}`, map[string]any{"p": provider0{}}, nil, false},
		{"sub-provider0-D-regular", "{{.p.D}}", "vD", map[string]any{"p": provider0{"vD"}}, nil, true},

		{"provider0Err-A-exists", "{{.A}}", "vA", provider0Err{}, nil, true},
		{"provider0Err-b-exists", "{{.b}}", "vb", provider0Err{}, nil, true},
		{"provider0Err-c-absent", "{{.c}}", `template: provider0Err-c-absent:1:2: executing "provider0Err-c-absent" at <.c>: can't evaluate field c in type template.provider0Err`, provider0Err{}, nil, false},
		{"provider0Err-err", "{{.err}}", `template: provider0Err-err:1:2: executing "provider0Err-err" at <.err>: error calling ("err"): expected`, provider0Err{}, nil, false},

		{"providerTemplate-name-exists", "{{.name}}", "providerTemplate-name-exists", providerTemplate{}, nil, true},
		{"providerTemplate-c-absent", "{{.c}}", `template: providerTemplate-c-absent:1:2: executing "providerTemplate-c-absent" at <.c>: can't evaluate field c in type template.providerTemplate`, providerTemplate{}, nil, false},

		{"providerSomeAny", "{{.P.some}}", "<someRoot>", someRoot{providerSomeAny{}}, nil, true},
		{"providerSomeFoo", "{{.P.some}}", "<someRoot>", someRoot{providerSomeFoo{}}, nil, true},
		{"providerSomeFoo-missed", "{{.P.some}}", `template: providerSomeFoo-missed:1:4: executing "providerSomeFoo-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeFoo{}}, nil, false},
		{"providerSomeExplicit", "{{.P.some}}", "<someRoot>", someRoot{providerSomeExplicit{}}, nil, true},
		{"providerSomeExplicit-missed", "{{.P.some}}", `template: providerSomeExplicit-missed:1:4: executing "providerSomeExplicit-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeExplicit{}}, nil, false},

		{"providerSomeAnyTemplate", "{{.P.some}}", "<someRoot>-providerSomeAnyTemplate", someRoot{providerSomeAnyTemplate{}}, nil, true},
		{"providerSomeFooTemplate", "{{.P.some}}", "<someRoot>-providerSomeFooTemplate", someRoot{providerSomeFooTemplate{}}, nil, true},
		{"providerSomeFooTemplate-missed", "{{.P.some}}", `template: providerSomeFooTemplate-missed:1:4: executing "providerSomeFooTemplate-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeFooTemplate{}}, nil, false},
		{"providerSomeExplicitTemplate", "{{.P.some}}", "<someRoot>-providerSomeExplicitTemplate", someRoot{providerSomeExplicitTemplate{}}, nil, true},
		{"providerSomeExplicitTemplate-missed", "{{.P.some}}", `template: providerSomeExplicitTemplate-missed:1:4: executing "providerSomeExplicitTemplate-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeExplicitTemplate{}}, nil, false},

		{"providerSomeTemplateAny", "{{.P.some}}", "<someRoot>-providerSomeTemplateAny", someRoot{providerSomeTemplateAny{}}, nil, true},
		{"providerSomeTemplateFoo", "{{.P.some}}", "<someRoot>-providerSomeTemplateFoo", someRoot{providerSomeTemplateFoo{}}, nil, true},
		{"providerSomeTemplateFoo-missed", "{{.P.some}}", `template: providerSomeTemplateFoo-missed:1:4: executing "providerSomeTemplateFoo-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeTemplateFoo{}}, nil, false},
		{"providerSomeTemplateExplicit", "{{.P.some}}", "<someRoot>-providerSomeTemplateExplicit", someRoot{providerSomeTemplateExplicit{}}, nil, true},
		{"providerSomeTemplateExplicit-missed", "{{.P.some}}", `template: providerSomeTemplateExplicit-missed:1:4: executing "providerSomeTemplateExplicit-missed" at <.P.some>: can't evaluate field some in type interface {}`, map[string]any{"P": providerSomeTemplateExplicit{}}, nil, false},

		{"sliceProviderString-0-exists", "{{.i0}}", "v0", sliceProviderString{"v0", "v1"}, nil, true},
		{"sliceProviderString-1-exists", "{{.i1}}", "v1", sliceProviderString{"v0", "v1"}, nil, true},
		{"sliceProviderString-2-absent", "{{.i2}}", `template: sliceProviderString-2-absent:1:2: executing "sliceProviderString-2-absent" at <.i2>: can't evaluate field i2 in type template.sliceProviderString`, sliceProviderString{"v0", "v1"}, nil, false},
	}

	b := new(strings.Builder)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tmpl *Template
			var err error
			tmpl, err = New(c.name).Option(c.options...).Parse(c.input)
			if err != nil {
				t.Fatalf("%s: parse error: %s", c.name, err)
			}
			b.Reset()
			err = tmpl.Execute(b, c.data)
			switch {
			case !c.ok && err == nil:
				t.Fatalf("expected error; got none")
			case c.ok && err != nil:
				t.Fatalf("unexpected execute error: %v", err)
			case !c.ok && err != nil:
				if c.output != err.Error() {
					t.Fatalf("expected error %q; got %q", c.output, err.Error())
				}
			}
			if err == nil {
				result := b.String()
				if result != c.output {
					t.Errorf("expected %q; got %q", c.output, result)
				}
			}
		})
	}
}

var errExpected = errors.New("expected")

type someType string

type someRoot struct {
	P any
}

func (s someRoot) Foo() string {
	return "foo"
}

func (s someRoot) String() string {
	return "<someRoot>"
}

type fooType interface {
	Foo() string
}

type provider0 struct {
	D string
}

func (p provider0) GetField(name string) (someType, bool) {
	switch name {
	case "A":
		return "vA", true
	case "b":
		return "vb", true
	default:
		return "", false
	}
}

type provider0Err struct{}

func (p provider0Err) GetField(name string) (someType, bool, error) {
	switch name {
	case "A":
		return "vA", true, nil
	case "b":
		return "vb", true, nil
	case "err":
		return "", false, errExpected
	default:
		return "", false, nil
	}
}

type providerTemplate struct{}

func (p providerTemplate) GetField(name string, tmpl *Template) (any, bool) {
	switch name {
	case "name":
		return tmpl.Name(), true
	default:
		return "", false
	}
}

type providerSomeAny struct{}

func (p providerSomeAny) GetField(name string, some any) (any, bool) {
	switch name {
	case "some":
		return some, true
	default:
		return nil, false
	}
}

type providerSomeFoo struct{}

func (p providerSomeFoo) GetField(name string, some fooType) (fooType, bool) {
	switch name {
	case "some":
		return some, true
	default:
		return nil, false
	}
}

type providerSomeExplicit struct{}

func (p providerSomeExplicit) GetField(name string, some someRoot) (someRoot, bool) {
	switch name {
	case "some":
		return some, true
	default:
		return someRoot{}, false
	}
}

type providerSomeAnyTemplate struct{}

func (p providerSomeAnyTemplate) GetField(name string, some any, tmpl *Template) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type providerSomeFooTemplate struct{}

func (p providerSomeFooTemplate) GetField(name string, some fooType, tmpl *Template) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type providerSomeExplicitTemplate struct{}

func (p providerSomeExplicitTemplate) GetField(name string, some someRoot, tmpl *Template) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type providerSomeTemplateAny struct{}

func (p providerSomeTemplateAny) GetField(name string, tmpl *Template, some any) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type providerSomeTemplateFoo struct{}

func (p providerSomeTemplateFoo) GetField(name string, tmpl *Template, some fooType) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type providerSomeTemplateExplicit struct{}

func (p providerSomeTemplateExplicit) GetField(name string, tmpl *Template, some someRoot) (string, bool) {
	switch name {
	case "some":
		return fmt.Sprintf("%v-%s", some, tmpl.Name()), true
	default:
		return "", false
	}
}

type sliceProviderString []string

func (p sliceProviderString) GetField(name string) (string, bool) {
	if !strings.HasPrefix(name, "i") {
		return "", false
	}
	i, err := strconv.ParseInt(name[1:], 10, 0)
	if err != nil {
		return "", false
	}
	if int(i) >= len(p) {
		return "", false
	}
	return p[i], true
}

type providerWithEmbedded struct {
	ProviderEmbedded
}

func (p providerWithEmbedded) GetField(name string) (someType, bool) {
	switch name {
	case "A":
		return "vA", true
	case "b":
		return "vb", true
	default:
		return "", false
	}
}

type ProviderEmbedded struct {
	D string
}

func (p ProviderEmbedded) GetField(name string) (string, bool) {
	switch name {
	case "c":
		return "vc", true
	default:
		return "", false
	}
}

type providerWithPrivateEmbedded struct {
	providerPrivateEmbedded
}

func (p providerWithPrivateEmbedded) GetField(name string) (someType, bool) {
	switch name {
	case "A":
		return "vA", true
	case "b":
		return "vb", true
	default:
		return "", false
	}
}

type providerPrivateEmbedded struct{}

func (p providerPrivateEmbedded) GetField(name string) (string, bool) {
	switch name {
	case "c":
		return "vc", true
	default:
		return "", false
	}
}
