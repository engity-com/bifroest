package template

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
)

const (
	maximumReadFileSize = 16 * 1024 * 1024 // 16MB
)

var (
	customFuncs = template.FuncMap{
		"firstMatching": firstMatching,
		"lastMatching":  lastMatching,
		"file":          file,
		"stat":          stat,
		"fileExists":    fileExists,
		"dirExists":     dirExists,
		"osJoin":        filepath.Join,
		"pathJoin":      path.Join,
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

type readFileArgs struct {
	filename string
	optional bool
}

func (this *readFileArgs) parseArgs(arg0 string, args []string) error {
	if len(args) > 0 {
		evalOpt := func(v string) error {
			switch v {
			case "optional":
				this.optional = true
				return nil
			default:
				return fmt.Errorf("illegal optional: %q", v)
			}
		}
		if err := evalOpt(arg0); err != nil {
			return err
		}
		for _, argN := range args[:len(args)-1] {
			if err := evalOpt(argN); err != nil {
				return err
			}
		}
		this.filename = args[len(args)-1]
	} else {
		this.filename = arg0
	}
	return nil
}

func file(arg0 string, args ...string) (string, error) {
	var fa readFileArgs
	if err := fa.parseArgs(arg0, args); err != nil {
		return "", err
	}
	if fa.filename == "" {
		if fa.optional {
			return "", nil
		}
		return "", fmt.Errorf("no file specified")
	}

	f, err := os.Open(fa.filename)
	if err != nil {
		if os.IsNotExist(err) && fa.optional {
			return "", nil
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, maximumReadFileSize)); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func stat(arg0 string, args ...string) (fs.FileInfo, error) {
	var fa readFileArgs
	if err := fa.parseArgs(arg0, args); err != nil {
		return nil, err
	}
	if fa.filename == "" {
		if fa.optional {
			return nil, nil
		}
		return nil, fmt.Errorf("no file specified")
	}

	fi, err := os.Stat(fa.filename)
	if err != nil {
		if os.IsNotExist(err) && fa.optional {
			return nil, nil
		}
		return nil, err
	}

	return fi, nil
}

func fileExists(filename string) (bool, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return !fi.IsDir(), nil
}

func dirExists(filename string) (bool, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return fi.IsDir(), nil
}
