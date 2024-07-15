package session

type State uint8

const (
	StateNew State = iota
	StateAuthorized
)
