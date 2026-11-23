package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/template"
)

type accountInventory struct {
	bind       binder
	management func(context.Context, *configuration.Flow, *authorization.AssumedLocalAuthentication) (authorization.LocalAccountView, error)
	project    func(*policyContext, *configuration.EnvironmentLocal) (environment.TargetProjection, error)
}

func admitLocalCommonTemplates(conf *configuration.EnvironmentLocal, sources []string) error {
	sources = append(sources, conf.Directory.String(), conf.PortForwardingAllowed.String())
	for _, values := range [][]template.String{conf.ShellCommand, conf.ExecCommandPrefix} {
		for _, value := range values {
			sources = append(sources, value.String())
		}
	}
	for _, source := range sources {
		if err := admitTemplate(source); err != nil {
			return err
		}
	}
	return nil
}

func (this accountInventory) projectLocal(ctx *policyContext, conf *configuration.EnvironmentLocal) (map[string]any, error) {
	// Admit every expression evaluated by the production selector, not the later
	// login/provisioning/runtime stages. No repository or native account is built.
	if err := admitLocalTargetTemplates(conf); err != nil {
		return nil, err
	}
	projection, err := this.project(ctx, conf)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"type": "local", "kind": projection.Kind()}
	for _, name := range []string{"account", "name", "requestedSID", "displayName", "groups", "skel", "shellCommand", "execCommandPrefix", "directory", "portForwardingAllowed"} {
		value, present := projection.Field(name)
		if !present {
			continue
		}
		value, err = localSelectorValue(name, value)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	// Normalize typed Go lists/IDs into the same exact Lua/report data vocabulary.
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, invalid("cannot normalize local selector projection")
	}
	normalized, err := normalizedJSON(raw)
	if err != nil {
		return nil, err
	}
	return normalized.(map[string]any), nil
}

func normalizedJSON(raw []byte) (any, error) {
	if len(raw) > maxSource {
		return nil, invalid("normalized selector size limit exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, invalid("invalid normalized selector")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, invalid("invalid normalized selector trailing data")
	}
	var visit func(any, int) (any, error)
	nodes := 0
	visit = func(value any, depth int) (any, error) {
		nodes++
		if nodes > maxNodes || depth > maxDepth {
			return nil, invalid("normalized selector structure limit exceeded")
		}
		switch v := value.(type) {
		case json.Number:
			number, err := v.Int64()
			if err != nil {
				return nil, invalid("invalid normalized selector integer")
			}
			return number, nil
		case []any:
			for i, item := range v {
				converted, err := visit(item, depth+1)
				if err != nil {
					return nil, err
				}
				v[i] = converted
			}
		case map[string]any:
			for key, item := range v {
				converted, err := visit(item, depth+1)
				if err != nil {
					return nil, err
				}
				v[key] = converted
			}
		case string:
			if len(v) > maxString {
				return nil, invalid("normalized selector string limit exceeded")
			}
		}
		return value, nil
	}
	return visit(value, 0)
}
