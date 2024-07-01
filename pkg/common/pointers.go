package common

func P[T any](a T) *T {
	return &a
}
