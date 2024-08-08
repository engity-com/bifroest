package errors

import (
	"errors"
	"fmt"
)

func Newf(pt Type, msg string, args ...any) *Error {
	return NewWithResultCausef(pt, msg, args...)
}

func NewWithResultCausef(pt Type, msg string, args ...any) *Error {
	buf := fmt.Errorf(msg, args...)
	return &Error{
		Message: buf.Error(),
		Cause:   errors.Unwrap(buf),
		Type:    pt,
	}
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
