package environment

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/connection"
)

type localTemplateContext struct {
	Request
	user    any
	managed bool
}

func (this localTemplateContext) GetField(name string) (any, bool, error) {
	if name == "connection" {
		view, err := connection.TemplateViewOf(this.Request)
		return view, true, err
	}
	if name == "user" {
		if this.user == nil {
			return nil, true, nil
		}
		return localTemplateUser{this.user, this.managed}, true, nil
	}
	if source, ok := this.Request.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return source.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}

type localTemplateUser struct {
	account any
	managed bool
}

func (this localTemplateUser) GetField(name string) (any, bool, error) {
	if name == "managed" {
		return this.managed, true, nil
	}
	if source, ok := this.account.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return source.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown user field %q", name)
}
