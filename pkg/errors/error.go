package errors

import "C"
import (
	"errors"
	"fmt"
	"github.com/engity/pam-oidc/pkg/pam"
	"log/syslog"
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

func As(err error) *Error {
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func ForceAs(err error) *Error {
	pe := As(err)
	if err != nil && pe == nil {
		pe = &Error{
			Message:     err.Error(),
			Cause:       err,
			Type:        TypeSystem,
			ResultCause: TypeSystem.ToResult(),
		}
	}
	return pe
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

func (this *Error) Syslog(ph *pam.Handle) {
	var lvl syslog.Priority

	switch this.Type {
	case TypeUser, TypePermission:
		lvl = syslog.LOG_WARNING
	case TypeNetwork:
		lvl = syslog.LOG_ERR
	case TypeNone:
		lvl = this.ResultCause.SyslogPriority()
	default:
		lvl = syslog.LOG_ERR
	}
	ph.Syslogf(lvl, this.Error())
}
