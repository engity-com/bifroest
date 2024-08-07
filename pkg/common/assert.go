package common

import "fmt"

func NotNil(v any, msgAndArgs ...any) {
	if v == nil {
		if len(msgAndArgs) > 0 {
			msg := msgAndArgs[0].(string)
			args := msgAndArgs[1:]
			panic(fmt.Errorf(msg, args...))
		}
		panic("value is nil")
	}
}
