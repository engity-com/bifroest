package template

import (
	"github.com/engity-com/bifroest/internal/text/template"
)

func NewTemplate(name, plain string) (*template.Template, error) {
	return withTemplateOptions(template.New(name).Funcs(allFuncs)).Parse(plain)
}

func withTemplateOptions(tmpl *template.Template) *template.Template {
	return tmpl.Option("missingkey=error", "invalid=nil", "nil=empty")
}
