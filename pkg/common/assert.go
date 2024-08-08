package common

import "fmt"

func MustNotNil(v any, msgAndArgs ...any) {
	if v == nil {
		if len(msgAndArgs) > 0 {
			msg := msgAndArgs[0].(string)
			args := msgAndArgs[1:]
			panic(fmt.Errorf(msg, args...))
		}
		panic("value is nil")
	}
}

func Must(v error, msgAndArgs ...any) {
	if v != nil {
		if len(msgAndArgs) > 0 {
			msg := msgAndArgs[0].(string) + ": %w"
			args := append(msgAndArgs[1:], v)
			panic(fmt.Errorf(msg, args...))
		}
		panic(v)
	}
}
