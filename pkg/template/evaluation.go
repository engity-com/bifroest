package template

import (
	"io"
	"io/fs"
	"os"
	"reflect"
	"time"

	"github.com/engity-com/bifroest/internal/text/template"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrEvaluationUnavailable   = errors.System.Newf("template evaluation is unavailable")
	ErrFunctionUnavailable     = errors.Config.Newf("template function is unavailable in controlled evaluation")
	ErrInvalidEvaluationSource = errors.System.Newf("template evaluation source returned no value")
)

// EvaluationContext opts typed Render calls into a controlled evaluation. It is
// an optional context capability, not a wrapper around the original data. An
// explicitly supplied nil/zero evaluation rejects template execution, never
// falling back to the host. Hard-coded values do not execute a template.
type EvaluationContext interface {
	TemplateEvaluation() *Evaluation
}

// EvaluationSources are explicit per-evaluation dependencies. Nil sources are
// unavailable. LookupEnv must distinguish a modeled absent variable (false,
// nil) from missing facts (an error); file providers must likewise reserve
// fs.ErrNotExist for modeled absence. Even optional file reads propagate other
// errors. Providers own confinement, consistency, cancellation and concurrency.
// No source is replaced with the process environment, filesystem or clock.
type EvaluationSources struct {
	LookupEnv func(string) (string, bool, error)
	OpenFile  func(string) (io.ReadCloser, error)
	StatFile  func(string) (fs.FileInfo, error)
	Now       func() (time.Time, error)
}

// Evaluation holds an immutable function selection, not the test's input data.
// Only inventoried local functions and explicitly bound sources are available.
// Other functions fail on use, including in firstMatching/lastMatching. Parsed
// templates and the production function registry are never modified.
//
// This is not a sandbox: data methods/getters and the supplied sources remain
// caller capabilities. Inputs must be isolated and execution/resource bounds
// must be enforced separately. Direct execution of a raw NewTemplate result
// retains its existing production semantics; this capability governs Render.
type Evaluation struct {
	functions template.FuncMap
}

func NewEvaluation(sources EvaluationSources) *Evaluation {
	result := &Evaluation{functions: make(template.FuncMap, len(allFuncs))}
	for name, function := range allFuncs {
		if evaluationFunctionKinds[name] == evaluationFunctionLocal {
			result.functions[name] = function
		} else {
			result.functions[name] = func(...any) (any, error) {
				return nil, unavailableFunction(name)
			}
		}
	}
	result.functions["firstMatching"] = func(plain string, list any) (string, error) {
		return matching("firstMatching", plain, list, false, result.execute)
	}
	result.functions["lastMatching"] = func(plain string, list any) (string, error) {
		return matching("lastMatching", plain, list, true, result.execute)
	}
	if lookup := sources.LookupEnv; lookup != nil {
		result.functions["env"] = func(key string, or ...string) (string, error) {
			value, err := lookupEnvironment(lookup, key, or...)
			if err != nil {
				return "", errors.System.Newf("%w", err)
			}
			return value, nil
		}
		result.functions["expandenv"] = func(plain string) (string, error) {
			var lookupErr error
			value := os.Expand(plain, func(key string) string {
				if lookupErr != nil {
					return ""
				}
				value, err := lookupEnvironment(lookup, key)
				lookupErr = err
				return value
			})
			if lookupErr != nil {
				return "", errors.System.Newf("%w", lookupErr)
			}
			return value, nil
		}
	}
	if source := sources.OpenFile; source != nil {
		open := func(name string) (io.ReadCloser, error) {
			reader, err := source(name)
			if err != nil {
				if !isNilEvaluationValue(reader) {
					common.IgnoreCloseError(reader)
				}
				return nil, err
			}
			if isNilEvaluationValue(reader) {
				return nil, ErrInvalidEvaluationSource
			}
			return reader, nil
		}
		result.functions["file"] = func(arg0 string, args ...string) (string, error) {
			return fileWith(open, arg0, args...)
		}
	}
	if source := sources.StatFile; source != nil {
		stat := func(name string) (fs.FileInfo, error) {
			info, err := source(name)
			if err == nil && isNilEvaluationValue(info) {
				return nil, ErrInvalidEvaluationSource
			}
			return info, err
		}
		result.functions["stat"] = func(arg0 string, args ...string) (fs.FileInfo, error) {
			return statWith(stat, arg0, args...)
		}
		result.functions["fileExists"] = func(name string) (bool, error) {
			return pathExistsWith(stat, name, false)
		}
		result.functions["dirExists"] = func(name string) (bool, error) {
			return pathExistsWith(stat, name, true)
		}
	}
	if now := sources.Now; now != nil {
		result.functions["now"] = func() (time.Time, error) {
			value, err := now()
			if err != nil {
				return time.Time{}, errors.System.Newf("%w", err)
			}
			return value, nil
		}
	}
	return result
}

func unavailableFunction(name string) error {
	return errors.Config.Newf("%w: %s", ErrFunctionUnavailable, name)
}

func executeTemplate(tmpl *template.Template, writer io.Writer, data any) error {
	evaluation, present, err := evaluationFrom(data)
	if err != nil {
		return errors.System.Newf("%w", err)
	}
	if present {
		return evaluation.execute(tmpl, writer, data)
	}
	return tmpl.Execute(writer, data)
}

func (this *Evaluation) execute(tmpl *template.Template, writer io.Writer, data any) error {
	if this == nil || this.functions == nil {
		return ErrEvaluationUnavailable
	}
	copyOfTemplate, err := tmpl.Clone()
	if err != nil {
		return errors.System.Newf("%w", err)
	}
	// Clone does not preserve options. Apply the same options as NewTemplate;
	// otherwise missing-key/nil behavior would differ from production.
	if err := withTemplateOptions(copyOfTemplate.Funcs(this.functions)).Execute(writer, data); err != nil {
		return errors.Config.Newf("%w", err)
	}
	return nil
}

func isNilEvaluationValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
