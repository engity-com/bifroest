package pam

import (
	"errors"
	"fmt"
)

type Error struct {
	Result    Result
	CauseType ErrorCauseType
	Message   string
	Cause     error
}

func (this *Error) Error() string {
	if len(this.Message) > 0 {
		return fmt.Sprintf("%v: %s", this.Result, this.Message)
	}
	return this.Result.String()
}

func (this *Error) Unwrap() error {
	return this.Cause
}

func AsError(err error) *Error {
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func ForceAsError(err error) *Error {
	pe := AsError(err)
	if err != nil && pe == nil {
		pe = &Error{
			Result:    ResultSystemErr,
			CauseType: ErrorCauseTypeSystem,
			Message:   err.Error(),
			Cause:     err,
		}
	}
	return pe
}

type ErrorCauseType uint8

const (
	ErrorCauseTypeSystem ErrorCauseType = iota
	ErrorCauseTypeConfiguration
	ErrorCauseTypeUser
)
