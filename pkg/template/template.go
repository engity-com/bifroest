package template

import (
	"text/template"
)

func NewTemplate(name, plain string) (*template.Template, error) {
	return template.New(name).
		Funcs(allFuncs).
		Option("missingkey=error").
		Parse(plain)
}
