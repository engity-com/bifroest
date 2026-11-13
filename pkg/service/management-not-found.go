package service

import (
	"errors"
	"io/fs"

	"github.com/engity-com/bifroest/pkg/session"
)

// Never disguise a simultaneous policy, cancellation or final-audit failure as
// a harmless missing entity. Only an exclusively missing-resource error tree fits.
type managementEntityMissingError struct{ error }

func (err *managementEntityMissingError) Unwrap() error { return err.error }

// Mark only a failed entity lookup, not later descriptor-close or final-audit IO.
func managementEntityLookupError(err error) error {
	if managementMissingErrorTree(err, false) {
		return &managementEntityMissingError{err}
	}
	return err
}
func managementOnlyNotFound(err error) bool { return managementMissingErrorTree(err, true) }
func managementMissingErrorTree(err error, marked bool) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*managementEntityMissingError); ok && marked {
		return true
	}
	if !marked && (err == session.ErrNoSuchSession || err == fs.ErrNotExist) {
		return true
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		causes := many.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !managementMissingErrorTree(cause, marked) {
				return false
			}
		}
		return true
	}
	inner := errors.Unwrap(err)
	if inner == nil {
		return !marked && errors.Is(err, fs.ErrNotExist)
	}
	return managementMissingErrorTree(inner, marked)
}
