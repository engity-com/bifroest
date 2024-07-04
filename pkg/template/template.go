package template

import (
	"github.com/Masterminds/sprig/v3"
	"strings"
	"text/template"
)

func NewTemplate(name, plain string) (*template.Template, error) {
	return template.New(name).
		Funcs(sprig.FuncMap()).
		Parse(plain)
}

func RenderString(name, plain string, data any) (string, error) {
	tmpl, err := template.New(name).
		Funcs(sprig.FuncMap()).
		Parse(plain)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
