package errors

type Type uint8

const (
	TypeUnknown Type = iota
	TypeSystem
	TypeConfig
	TypeNetwork
	TypeUser
	TypePermission
)
