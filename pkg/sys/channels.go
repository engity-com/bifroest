package sys

func IsClosedChan[T any](c <-chan T) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
