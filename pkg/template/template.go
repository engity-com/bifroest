package template

import (
	"github.com/engity-com/bifroest/internal/text/template"
)

func NewTemplate(name, plain string) (*template.Template, error) {
	return template.New(name).
		Funcs(allFuncs).
		Option("missingkey=error", "invalid=nil", "nil=empty").
		Parse(plain)
}
