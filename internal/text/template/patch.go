package template

import (
	"fmt"
	"reflect"
	"text/template/parse"
)

var (
	templatePT = reflect.TypeFor[*Template]()
	errorT     = reflect.TypeFor[error]()
	boolT      = reflect.TypeFor[bool]()
)

func (s *state) tryEvalAsGetter(dot reflect.Value, fieldName string, node parse.Node, ptr reflect.Value) (reflect.Value, bool) {
	res, ok := s.tryEvalAsGetterFor(dot, fieldName, node, ptr)
	if ok {
		return res, true
	}

	if ptr.Kind() == reflect.Ptr {
		ptr = ptr.Elem()
	}

	if !ptr.IsValid() {
		return reflect.Value{}, false
	}

	ptrT := ptr.Type()
	if ptrT.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}

	numFieldT := ptrT.NumField()
	for i := 0; i < numFieldT; i++ {
		fieldT := ptrT.Field(i)
		if !fieldT.Anonymous || !fieldT.IsExported() {
			continue
		}
		field := ptr.Field(i)
		if field.Kind() == reflect.Interface {
			field = field.Elem()
		}
		if field.Kind() != reflect.Pointer && field.CanAddr() {
			field = field.Addr()
		}
		if res, ok = s.tryEvalAsGetterFor(dot, fieldName, node, field); ok {
			return res, true
		}
	}

	return reflect.Value{}, false
}

func (s *state) tryEvalAsGetterFor(dot reflect.Value, fieldName string, node parse.Node, ptr reflect.Value) (reflect.Value, bool) {
	method := ptr.MethodByName("GetField")
	if !method.IsValid() {
		return reflect.Value{}, false
	}

	methodT := method.Type()
	dotT := dot.Type()
	argc := methodT.NumIn()
	retc := methodT.NumOut()
	if argc < 1 || retc < 2 || retc > 3 {
		return reflect.Value{}, false
	}

	if methodT.In(0).Kind() != reflect.String {
		return reflect.Value{}, false
	}

	if methodT.Out(1) != boolT {
		return reflect.Value{}, false
	}
	if retc == 3 && methodT.Out(2) != errorT {
		return reflect.Value{}, false
	}

	argv := make([]reflect.Value, argc)
	argv[0] = reflect.ValueOf(fieldName)
	for i := 1; i < argc; i++ {
		nT := methodT.In(i)
		if nT == templatePT {
			argv[i] = reflect.ValueOf(s.tmpl)
		} else if dotT.AssignableTo(nT) {
			argv[i] = dot
		} else {
			return reflect.Value{}, false
		}
	}

	execute := func(method reflect.Value, argv []reflect.Value) (_ reflect.Value, _ bool, err error) {
		defer func() {
			if r := recover(); r != nil {
				if e, ok := r.(error); ok {
					err = e
				} else {
					err = fmt.Errorf("%v", r)
				}
			}
		}()
		ret := method.Call(argv)
		if len(ret) > 2 && !ret[2].IsNil() {
			return reflect.Value{}, false, ret[2].Interface().(error)
		}
		return ret[0], ret[1].Interface().(bool), nil
	}

	v, ok, err := execute(method, argv)
	if err != nil {
		s.at(node)

		signature := fmt.Sprintf("%s(%q", methodT.Name(), fieldName)
		for i := 1; i < argc; i++ {
			signature += fmt.Sprintf(", %v", methodT.In(i))
		}
		signature += ")"

		s.errorf("error calling %s: %w", signature, err)
	}

	if v.Type() == reflectValueType {
		v = v.Interface().(reflect.Value)
	}

	return v, ok
}
