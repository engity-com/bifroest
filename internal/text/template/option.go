// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the code to handle template options.

package template

import "strings"

// missingKeyAction defines how to respond to indexing a map with a key that is not present.
type missingKeyAction int

const (
	mapInvalid   missingKeyAction = iota // Return an invalid reflect.Value.
	mapZeroValue                         // Return the zero value for the map element.
	mapError                             // Error out
)

type invalidAction uint8

const (
	invalidPrintNoValue invalidAction = iota
	invalidPrintEmpty
	invalidAsNil
)

type nilAction uint8

const (
	nilPrintNil nilAction = iota
	nilPrintEmpty
)

type option struct {
	missingKey missingKeyAction
	onInvalid  invalidAction
	onNil      nilAction
}

// Option sets options for the template. Options are described by
// strings, either a simple string or "key=value". There can be at
// most one equals sign in an option string. If the option string
// is unrecognized or otherwise invalid, Option panics.
//
// Known options:
//
// missingkey: Control the behavior during execution if a map is
// indexed with a key that is not present in the map.
//
//	"missingkey=default" or "missingkey=invalid"
//		The default behavior: Do nothing and continue execution.
//		If printed, the result of the index operation is the string
//		"<no value>".
//	"missingkey=zero"
//		The operation returns the zero value for the map type's element.
//	"missingkey=error"
//		Execution stops immediately with an error.
//
// invalid: Controls what happen if invalid values are used.
//
//	"invalid=default" or "invalid=print"
//		The default behavior will print "<no value>".
//	"invalid=empty"
//		Will print "".
//	"invalid=nil"
//		Will treat this value as nil.
//
// nil: Controls what happen if nil is used.
//
//	"nil=default" or "nil=print"
//		The default behavior will print "<nil>".
//	"nil=empty"
//		Will print "".
func (t *Template) Option(opt ...string) *Template {
	t.init()
	for _, s := range opt {
		t.setOption(s)
	}
	return t
}

func (t *Template) setOption(opt string) {
	if opt == "" {
		panic("empty option string")
	}
	// key=value
	if key, value, ok := strings.Cut(opt, "="); ok {
		switch key {
		case "missingkey":
			switch value {
			case "invalid", "default":
				t.option.missingKey = mapInvalid
				return
			case "zero":
				t.option.missingKey = mapZeroValue
				return
			case "error":
				t.option.missingKey = mapError
				return
			}
		case "invalid":
			switch value {
			case "print", "default":
				t.option.onInvalid = invalidPrintNoValue
				return
			case "empty":
				t.option.onInvalid = invalidPrintEmpty
				return
			case "nil":
				t.option.onInvalid = invalidAsNil
				return
			}
		case "nil":
			switch value {
			case "print", "default":
				t.option.onNil = nilPrintNil
				return
			case "empty":
				t.option.onNil = nilPrintEmpty
				return
			}
		}
	}
	panic("unrecognized option: " + opt)
}
