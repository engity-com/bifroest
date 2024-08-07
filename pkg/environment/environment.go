package environment

import "io"

type Environment interface {
	WillBeAccepted(Request) (bool, error)
	Banner(Request) (io.ReadCloser, error)
	Run(Task) error
}