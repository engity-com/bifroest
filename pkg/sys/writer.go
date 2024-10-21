package sys

type CloseWriter interface {
	CloseWrite() error
}
