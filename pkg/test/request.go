package test

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

// encoding/json repairs malformed UTF-8 and maps null to pointer/string zero
// values. Explicit request facts must not silently turn into different strings
// or missing/default values before the production validators see them.
func validateRequestStrings(raw any) error {
	fields, _ := raw.(map[string]any)
	for key, value := range fields {
		if !strings.EqualFold(key, "request") {
			continue
		}
		request, _ := value.(map[string]any)
		for _, value := range request {
			if text, ok := value.(string); !ok || !utf8.ValidString(text) {
				return invalid("invalid request string encoding")
			}
		}
	}
	return nil
}

func newOfflineRequest(ctx context.Context, input requestInput) (*offlineRequest, error) {
	if input.RequestingName == nil {
		return nil, invalid("requesting name was not modeled")
	}
	transport := connection.TransportSsh
	if input.Transport != nil {
		transport = *input.Transport
	}
	selection := connection.Selection{Transport: transport}
	method := authorization.LoginMethod(input.Method)
	if method == "" {
		method = authorization.LoginMethodPassword
	}
	if method != authorization.LoginMethodPassword && method != authorization.LoginMethodKeyboardInteractive && (transport != connection.TransportHttp || method != authorization.LoginMethodOidc) {
		return nil, invalid("request authentication method is outside the offline slice")
	}
	name := *input.RequestingName
	origin := ""
	switch transport {
	case connection.TransportSsh:
		if input.Host != nil || input.Slug != nil {
			return nil, invalid("SSH requests must not contain HTTP host or slug")
		}
		if name == "" || len(name) > 128 || (authentication.Identity{Principal: name, Issuer: "request", Subject: "request"}).Validate() != nil {
			return nil, invalid("invalid requesting name")
		}
	case connection.TransportHttp:
		if input.Host == nil || input.Slug == nil {
			return nil, invalid("HTTP authority and slug must be modeled explicitly")
		}
		if !connection.ValidHttpLoginUser(name) {
			return nil, invalid("invalid HTTP requesting name")
		}
		selection.Host, selection.Slug = *input.Host, *input.Slug
		var err error
		origin, err = net.CanonicalHttpsOrigin(*input.Host)
		if err != nil {
			return nil, invalid("invalid HTTP request authority")
		}
	default:
		return nil, invalid("request transport is outside the offline slice")
	}
	selection, err := selection.Canonical()
	if err != nil {
		return nil, invalid("invalid request selection")
	}
	return &offlineRequest{ctx: ctx, name: name, selection: selection, origin: origin, method: method, evaluation: template.NewEvaluation(template.EvaluationSources{})}, nil
}

func (this *offlineRequest) Selection() connection.Selection            { return this.selection }
func (this *offlineRequest) HttpLoginMethod() authorization.LoginMethod { return this.method }
func (this *offlineRequest) HttpLoginOrigin() string                    { return this.origin }

func (this *offlineRequest) view() map[string]any {
	result := map[string]any{"transport": string(this.selection.Transport), "method": string(this.method), "requestingName": this.name}
	if this.selection.Transport == connection.TransportHttp {
		result["host"], result["origin"], result["slug"] = this.selection.Host, this.origin, this.selection.Slug
	}
	return result
}
