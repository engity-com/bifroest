package template

import (
	"github.com/Masterminds/sprig/v3"
	"text/template"
)

func NewTemplate(name, plain string) (*template.Template, error) {
	return template.New(name).
		Funcs(sprig.FuncMap()).
		Option("missingkey=error").
		Parse(plain)
}
