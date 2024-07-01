package pam

import "fmt"

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

type ErrorCauseType uint8

const (
	ErrorCauseTypeSystem ErrorCauseType = iota
	ErrorCauseTypeConfiguration
	ErrorCauseTypeUser
)
