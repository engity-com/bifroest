package template

import (
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"reflect"
	"strings"
	"text/template"
)

var (
	customFuncs = template.FuncMap{
		"firstMatching": firstMatching,
		"lastMatching":  lastMatching,
	}

	allFuncs template.FuncMap
)

func init() {
	sfm := sprig.TxtFuncMap()
	allFuncs = make(template.FuncMap, len(sfm)+len(customFuncs))
	for k, v := range sfm {
		allFuncs[k] = v
	}
	for k, v := range customFuncs {
		allFuncs[k] = v
	}
}

func firstMatching(tmpl string, list any) (string, error) {
	t, err := NewTemplate("firstMatching", tmpl)
	if err != nil {
		return "", fmt.Errorf("'firstMatching' cannot parse template: %w", err)
	}

	tp := reflect.TypeOf(list).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		rl := reflect.ValueOf(list)

		l := rl.Len()
		for i := 0; i < l; i++ {
			var buf strings.Builder
			if err := t.Execute(&buf, rl.Index(i).Interface()); err != nil {
				return "", fmt.Errorf("#%d element cannot be evaluated: %w", i, err)
			}
			if buf.Len() > 0 {
				return buf.String(), nil
			}
		}
		return "", nil
	default:
		return "", fmt.Errorf("cannot do firstMatching on element kind %s", tp)
	}

}

func lastMatching(tmpl string, list any) (string, error) {
	t, err := NewTemplate("lastMatching", tmpl)
	if err != nil {
		return "", fmt.Errorf("'lastMatching' cannot parse template: %w", err)
	}

	var result string
	tp := reflect.TypeOf(list).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		rl := reflect.ValueOf(list)

		l := rl.Len()
		for i := 0; i < l; i++ {
			var buf strings.Builder
			if err := t.Execute(&buf, rl.Index(i).Interface()); err != nil {
				return "", fmt.Errorf("#%d element cannot be evaluated: %w", i, err)
			}
			if buf.Len() > 0 {
				result = buf.String()
			}
		}
		return result, nil
	default:
		return "", fmt.Errorf("cannot do lastMatching on element kind %s", tp)
	}

}
