package template

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/engity-com/bifroest/internal/text/template"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
	"golang.org/x/crypto/ssh"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"
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
		"fingerprint":   fingerprint,
		"format":        format,
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
			elem := rl.Index(i).Interface()
			if err := t.Execute(&buf, elem); err != nil {
				return "", fmt.Errorf("#%d element cannot be evaluated: %w", i, err)
			}
			if buf.Len() > 0 {
				if v := buf.String(); !isFalse(v) {
					return v, nil
				}
			}
		}
		return "", nil
	default:
		return "", fmt.Errorf("cannot do firstMatching on element kind %s", tp)
	}
}

func isFalse(what string) bool {
	switch what {
	case "false", "0", "<nil>", "", "off", "no":
		return true
	default:
		return false
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
				if v := buf.String(); !isFalse(v) {
					result = v
				}
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
		if sys.IsNotExist(err) && fa.optional {
			return "", nil
		}
		return "", err
	}
	defer common.IgnoreCloseError(f)

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
		if sys.IsNotExist(err) && fa.optional {
			return nil, nil
		}
		return nil, err
	}

	return fi, nil
}

func fileExists(filename string) (bool, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		if sys.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return !fi.IsDir(), nil
}

func dirExists(filename string) (bool, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		if sys.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return fi.IsDir(), nil
}

func fingerprint(arg any, args ...any) (string, error) {
	args = append([]any{arg}, args...)
	what := args[len(args)-1]
	args = args[:len(args)-1]
	switch v := what.(type) {
	case ssh.PublicKey:
		return fingerprintPublicKey(v, args...)
	default:
		return "", fmt.Errorf("unsupported type %T", v)
	}
}

func fingerprintPublicKey(what ssh.PublicKey, opts ...any) (string, error) {
	modern := false
	long := true

	for _, opt := range opts {
		switch opt {
		case "sha", "modern":
			modern = true
		case "md5", "legacy":
			modern = false
		case "long":
			long = true
		case "short":
			long = false
		default:
			return "", fmt.Errorf("illegal option: %v", opt)
		}
	}

	if modern {
		if long {
			ssh.FingerprintSHA256(what)
		}
		sum := sha256.Sum256(what.Marshal())
		return base64.RawStdEncoding.EncodeToString(sum[:]), nil
	} else {
		result := ssh.FingerprintLegacyMD5(what)
		if long {
			result = what.Type() + ":" + result
		}
		return result, nil
	}
}

func format(arg any, args ...any) (string, error) {
	args = append([]any{arg}, args...)
	what := args[len(args)-1]
	args = args[:len(args)-1]
	switch v := what.(type) {
	case time.Time:
		return formatDate(&v, args...)
	case *time.Time:
		return formatDate(v, args...)
	default:
		return "", fmt.Errorf("unsupported type %T", v)
	}
}

func formatDate(what *time.Time, opts ...any) (string, error) {
	layout := time.Layout
	if len(opts) > 0 {
		switch opts[0] {
		case "default":
			layout = time.Layout
		case "ansic":
			layout = time.ANSIC
		case "unix":
			layout = time.UnixDate
		case "ruby":
			layout = time.RubyDate
		case "rfc822":
			layout = time.RFC822
		case "rfc822z":
			layout = time.RFC822Z
		case "rfc850":
			layout = time.RFC850
		case "rfc1123":
			layout = time.RFC1123
		case "rfc1123z":
			layout = time.RFC1123Z
		case "rfc3339":
			layout = time.RFC3339
		case "rfc3339Nano":
			layout = time.RFC3339Nano
		case "kitchen":
			layout = time.Kitchen
		case "stamp":
			layout = time.Stamp
		case "stampMilli":
			layout = time.StampMilli
		case "stampMicro":
			layout = time.StampMicro
		case "stampNano":
			layout = time.StampNano
		case "dateTime":
			layout = time.DateTime
		case "dateTimeT":
			layout = "2006-01-02 15:04:05 MST"
		case "date", "dateOnly":
			layout = time.DateOnly
		case "time", "timeOnly":
			layout = time.TimeOnly
		default:
			layout = fmt.Sprint(opts[0])
		}
	} else if len(opts) > 1 {
		for _, opt := range opts[1:] {
			return "", fmt.Errorf("illegal option: %v", opt)
		}
	}

	return what.Format(layout), nil
}
