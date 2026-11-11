package session

import "context"

type contextEnabled interface {
	Context() context.Context
}
