package errors

import (
	"errors"
	"fmt"
)

func Newf(t Type, msg string, args ...any) *Error {
	buf := fmt.Errorf(msg, args...)
	err := errors.Unwrap(buf)
	var ee *Error
	if errors.As(err, &ee) {
		t = ee.Type
	}
	return &Error{
		Message: buf.Error(),
		Cause:   err,
		Type:    t,
	}
}

func IsType(err error, t Type, otherT ...Type) bool {
	var ee *Error
	if errors.As(err, &ee) {
		if ee.Type == t {
			return true
		}
		for _, ot := range otherT {
			if ee.Type == ot {
				return true
			}
		}
		return IsType(ee.Cause, t, otherT...)
	}
	return false
}

type Error struct {
	Message string
	Cause   error
	Type    Type
}

func (this *Error) Error() string {
	return this.Message
}

func (this *Error) Unwrap() error {
	return this.Cause
}

func IsError(err error) (eErr *Error, ok bool) {
	ok = As(err, &eErr)
	return
}
