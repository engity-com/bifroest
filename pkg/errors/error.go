package errors

import (
	"errors"
	"fmt"
	"github.com/engity/pam-oidc/pkg/pam"
)

func Newf(pt Type, msg string, args ...any) *Error {
	return NewWithResultCausef(pt, pt.ToResult(), msg, args...)
}

func NewWithResultCausef(pt Type, resultCause pam.Result, msg string, args ...any) *Error {
	buf := fmt.Errorf(msg, args...)
	return &Error{
		Message:     buf.Error(),
		Cause:       errors.Unwrap(buf),
		ResultCause: resultCause,
		Type:        pt,
	}
}

type Error struct {
	Message     string
	Cause       error
	Type        Type
	ResultCause pam.Result
}

func (this *Error) Error() string {
	return this.Message
}

func (this *Error) Unwrap() error {
	return this.Cause
}
