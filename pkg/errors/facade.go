package errors

import "errors"

// Is just a facade for errors.Is
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As just a facade for errors.As
func As(err error, target any) bool {
	//goland:noinspection GoErrorsAs
	return errors.As(err, target)
}

// Unwrap just a facade for errors.Unwrap
func Unwrap(err error) error {
	return errors.Unwrap(err)
}
