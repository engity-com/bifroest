package authorization

import (
	"fmt"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

type oidcLoginMessageContext struct {
	request      Request
	url, code    string
	codeRequired bool
}

func (this *oidcLoginMessageContext) TemplateEvaluationParent() any { return this.request }

func (this *oidcLoginMessageContext) GetField(name string) (any, bool, error) {
	switch name {
	case "url":
		return this.url, true, nil
	case "code":
		return this.code, true, nil
	case "codeRequired":
		return this.codeRequired, true, nil
	default:
		if parent, ok := this.request.(interface {
			GetField(string) (any, bool, error)
		}); ok {
			return parent.GetField(name)
		}
		return nil, false, fmt.Errorf("unknown login message field %q", name)
	}
}

// Only SSH uses operator-supplied prose. The WebUI consumes structured data.
func RenderOidcSshLoginMessage(req Request, configured template.String, address, code string, codeRequired bool) (string, error) {
	if configured.IsZero() {
		configured = configuration.DefaultAuthorizationOidcSshLoginMessage
	}
	message, err := configured.Render(&oidcLoginMessageContext{request: req, url: address, code: code, codeRequired: codeRequired})
	if err != nil || len(message) == 0 || len(message) > 8<<10 || !utf8.ValidString(message) {
		return "", fmt.Errorf("cannot render SSH login message")
	}
	return message, nil
}
