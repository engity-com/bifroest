package core

import "fmt"

type Result uint8

const (
	ResultSuccess Result = iota
	ResultSystemErr
	ResultConfigurationErr
	ResultRequestingNameForbidden
	ResultOidcAuthorizeTimeout
	ResultOidcAuthorizeFailed
	ResultRequirementResolutionFailed
	ResultLoginAllowedResolutionFailed
	ResultLoginForbidden
	ResultUserEnsuringFailed
	ResultNoSuchUser
	ResultIgnore
)

func (this Result) String() string {
	switch this {
	case ResultSuccess:
		return "success"
	case ResultSystemErr:
		return "system error"
	case ResultConfigurationErr:
		return "configuration related error"
	case ResultRequestingNameForbidden:
		return "requesting name forbidden"
	case ResultOidcAuthorizeTimeout:
		return "oidc authorize timeout"
	case ResultOidcAuthorizeFailed:
		return "oidc authorize failed"
	case ResultRequirementResolutionFailed:
		return "requirement resolution failed"
	case ResultLoginAllowedResolutionFailed:
		return "login allowed resolution failed"
	case ResultLoginForbidden:
		return "login forbidden"
	case ResultUserEnsuringFailed:
		return "user ensuring failed"
	case ResultNoSuchUser:
		return "no such user"
	case ResultIgnore:
		return "ignore"
	default:
		return fmt.Sprintf("unknown result %d", this)
	}
}

func (this Result) IsSuccess() bool {
	switch this {
	case ResultSuccess:
		return true
	default:
		return false
	}
}
