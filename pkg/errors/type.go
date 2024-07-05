package errors

import (
	"github.com/engity/pam-oidc/pkg/pam"
)

type Type uint8

const (
	TypeNone Type = iota
	TypeSystem
	TypeConfig
	TypeNetwork
	TypeUser
	TypePermission
)

func (this Type) ToResult() pam.Result {
	switch this {
	case TypeUser, TypePermission:
		return pam.ResultCredentialsInsufficient
	case TypeNetwork:
		return pam.ResultAuthInfoUnavailable
	default:
		return pam.ResultAuthErr
	}
}
