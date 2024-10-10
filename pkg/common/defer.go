package common

import "io"

func KeepError(target *error, when func() error) {
	if when != nil {
		if err := when(); err != nil && *target == nil {
			*target = err
		}
	}
}

func KeepCloseError(target *error, when io.Closer) {
	if when != nil {
		KeepError(target, when.Close)
	}
}

func IgnoreError(when func() error) {
	if when != nil {
		_ = when()
	}
}

func IgnoreCloseError(when io.Closer) {
	if when != nil {
		IgnoreError(when.Close)
	}
}

func DoIfFalse(assertToBeTrue *bool, otherwise func()) {
	if otherwise != nil && !*assertToBeTrue {
		otherwise()
	}
}

func IgnoreErrorIfFalse(assertToBeTrue *bool, otherwise func() error) {
	DoIfFalse(assertToBeTrue, func() {
		if otherwise != nil {
			_ = otherwise()
		}
	})
}

func IgnoreCloseErrorIfFalse(assertToBeTrue *bool, otherwise io.Closer) {
	if otherwise != nil {
		IgnoreErrorIfFalse(assertToBeTrue, otherwise.Close)
	}
}
