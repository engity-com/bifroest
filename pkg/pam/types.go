package pam

import (
	"errors"
	"fmt"
	"log/syslog"
)

type Result uint8

const (
	// ResultSuccess indicates successful function return.
	ResultSuccess = Result(_PAM_SUCCESS)
	// ResultOpenErr indicates dlopen() failure when dynamically  loading a service module.
	ResultOpenErr = Result(_PAM_OPEN_ERR)
	// ResultSymbolErr means symbol not found.
	ResultSymbolErr = Result(_PAM_SYMBOL_ERR)
	// ResultServiceErr indicates an error in service module.
	ResultServiceErr = Result(_PAM_SERVICE_ERR)
	// ResultSystemErr indicates a system error.
	ResultSystemErr = Result(_PAM_SYSTEM_ERR)
	// ResultBufferErr indicates memory buffer error.
	ResultBufferErr = Result(_PAM_BUF_ERR)
	// ResultPermissionDenied indicates permission denied.
	ResultPermissionDenied = Result(_PAM_PERM_DENIED)
	// ResultAuthErr indicates authentication failure.
	ResultAuthErr = Result(_PAM_AUTH_ERR)
	// ResultCredentialsInsufficient indicates can not access authentication data due to insufficient credentials.
	ResultCredentialsInsufficient = Result(_PAM_CRED_INSUFFICIENT)
	// ResultAuthInfoUnavailable indicates underlying authentication service  can not retrieve authentication information.
	ResultAuthInfoUnavailable = Result(_PAM_AUTHINFO_UNAVAIL)
	// ResultUserUnknown indicates user not known to the underlying authentication module.
	ResultUserUnknown = Result(_PAM_USER_UNKNOWN)
	// ResultMaxTries indicates an authentication service has maintained a retry count which has  been reached.
	// No further retries should be attempted.
	ResultMaxTries = Result(_PAM_MAXTRIES)
	// ResultNewAuthTokenRequired indicates new authentication token required.
	// This is normally returned if the machine security policies require that the password should be changed
	// because the password is NULL, or it has aged.
	ResultNewAuthTokenRequired = Result(_PAM_NEW_AUTHTOK_REQD)
	// ResultAccountExpired indicates user account has expired.
	ResultAccountExpired = Result(_PAM_ACCT_EXPIRED)
	// ResultSessionErr indicates can not make/remove an entry for the specified session.
	ResultSessionErr = Result(_PAM_SESSION_ERR)
	// ResultCredentialsUnavailable indicates underlying authentication service can not retrieve user credentials unavailable.
	ResultCredentialsUnavailable = Result(_PAM_CRED_UNAVAIL)
	// ResultCredentialsExpired indicates user credentials expired.
	ResultCredentialsExpired = Result(_PAM_CRED_EXPIRED)
	// ResultCredentialsErr indicates failure setting user credentials.
	ResultCredentialsErr = Result(_PAM_CRED_ERR)
	// ResultNoModuleData indicates no module specific data is present.
	ResultNoModuleData = Result(_PAM_NO_MODULE_DATA)
	// ResultConversationErr indicates conversation error.
	ResultConversationErr = Result(_PAM_CONV_ERR)
	// ResultAuthTokenErr indicates authentication token manipulation error.
	ResultAuthTokenErr = Result(_PAM_AUTHTOK_ERR)
	// ResultAuthTokenRecoveryErr indicates authentication information cannot be recovered.
	ResultAuthTokenRecoveryErr = Result(_PAM_AUTHTOK_RECOVERY_ERR)
	// ResultAuthTokenLockBusy indicates authentication token lock busy.
	ResultAuthTokenLockBusy = Result(_PAM_AUTHTOK_LOCK_BUSY)
	// ResultAuthTokenDisableAging indicates authentication token aging disabled.
	ResultAuthTokenDisableAging = Result(_PAM_AUTHTOK_DISABLE_AGING)
	// ResultTryAgain indicates preliminary check by password service.
	ResultTryAgain = Result(_PAM_TRY_AGAIN)
	// ResultIgnore indicates Ignore underlying account module regardless of whether the control flag is required,
	// optional, or sufficient.
	ResultIgnore = Result(_PAM_IGNORE)
	// ResultAbort indicates critical error (module fail now request).
	ResultAbort = Result(_PAM_ABORT)
	// ResultAuthTokenExpired indicates user's authentication token has expired.
	ResultAuthTokenExpired = Result(_PAM_AUTHTOK_EXPIRED)
	// ResultModuleUnknown indicates module is not known.
	ResultModuleUnknown = Result(_PAM_MODULE_UNKNOWN)
	// ResultBadItem indicates bad item passed to pam_*_item().
	ResultBadItem = Result(_PAM_BAD_ITEM)
	// ResultConversationAgain indicates conversation function is event driven and data is not available yet.
	ResultConversationAgain = Result(_PAM_CONV_AGAIN)
	// ResultIncomplete indicates please call this function again to complete authentication stack. Before calling again,
	// verify that conversation is completed.
	ResultIncomplete = Result(_PAM_INCOMPLETE)
)

func (this Result) String() string {
	switch this {
	case ResultSuccess:
		return "success"
	case ResultOpenErr:
		return "open error"
	case ResultSymbolErr:
		return "symbol error"
	case ResultServiceErr:
		return "service error"
	case ResultSystemErr:
		return "system error"
	case ResultBufferErr:
		return "buffer error"
	case ResultPermissionDenied:
		return "permission denied"
	case ResultAuthErr:
		return "authentication error"
	case ResultCredentialsInsufficient:
		return "credentials insufficient"
	case ResultAuthInfoUnavailable:
		return "authentication information unavailable"
	case ResultUserUnknown:
		return "user unknown"
	case ResultMaxTries:
		return "maximum tries"
	case ResultNewAuthTokenRequired:
		return "new authentication token required"
	case ResultAccountExpired:
		return "account expired"
	case ResultSessionErr:
		return "session error"
	case ResultCredentialsUnavailable:
		return "credentials unavailable"
	case ResultCredentialsExpired:
		return "credentials expired"
	case ResultCredentialsErr:
		return "credentials error"
	case ResultNoModuleData:
		return "no module data"
	case ResultConversationErr:
		return "conversation error"
	case ResultAuthTokenErr:
		return "authentication token error"
	case ResultAuthTokenRecoveryErr:
		return "authentication token recovery error"
	case ResultAuthTokenLockBusy:
		return "authentication token lock busy"
	case ResultAuthTokenDisableAging:
		return "authentication token disable aging"
	case ResultTryAgain:
		return "try again"
	case ResultIgnore:
		return "ignore"
	case ResultAbort:
		return "abort"
	case ResultAuthTokenExpired:
		return "authentication token expired"
	case ResultModuleUnknown:
		return "module unknown"
	case ResultBadItem:
		return "bad item"
	case ResultConversationAgain:
		return "conversation again"
	case ResultIncomplete:
		return "incomplete"
	default:
		return "unknown"
	}
}

func (this Result) SyslogPriority() syslog.Priority {
	switch this {
	case ResultSuccess:
		return syslog.LOG_INFO
	case ResultOpenErr:
		return syslog.LOG_ERR
	case ResultSymbolErr:
		return syslog.LOG_ERR
	case ResultServiceErr:
		return syslog.LOG_ERR
	case ResultSystemErr:
		return syslog.LOG_ERR
	case ResultBufferErr:
		return syslog.LOG_ERR
	case ResultPermissionDenied:
		return syslog.LOG_WARNING
	case ResultAuthErr:
		return syslog.LOG_ERR
	case ResultCredentialsInsufficient:
		return syslog.LOG_WARNING
	case ResultAuthInfoUnavailable:
		return syslog.LOG_WARNING
	case ResultUserUnknown:
		return syslog.LOG_WARNING
	case ResultMaxTries:
		return syslog.LOG_WARNING
	case ResultNewAuthTokenRequired:
		return syslog.LOG_WARNING
	case ResultAccountExpired:
		return syslog.LOG_WARNING
	case ResultSessionErr:
		return syslog.LOG_ERR
	case ResultCredentialsUnavailable:
		return syslog.LOG_WARNING
	case ResultCredentialsExpired:
		return syslog.LOG_WARNING
	case ResultCredentialsErr:
		return syslog.LOG_ERR
	case ResultNoModuleData:
		return syslog.LOG_ERR
	case ResultConversationErr:
		return syslog.LOG_ERR
	case ResultAuthTokenErr:
		return syslog.LOG_ERR
	case ResultAuthTokenRecoveryErr:
		return syslog.LOG_ERR
	case ResultAuthTokenLockBusy:
		return syslog.LOG_ERR
	case ResultAuthTokenDisableAging:
		return syslog.LOG_ERR
	case ResultTryAgain:
		return syslog.LOG_WARNING
	case ResultIgnore:
		return syslog.LOG_ERR
	case ResultAbort:
		return syslog.LOG_CRIT
	case ResultAuthTokenExpired:
		return syslog.LOG_WARNING
	case ResultModuleUnknown:
		return syslog.LOG_ERR
	case ResultBadItem:
		return syslog.LOG_ERR
	case ResultConversationAgain:
		return syslog.LOG_WARNING
	case ResultIncomplete:
		return syslog.LOG_WARNING
	default:
		return syslog.LOG_ERR
	}
}

func (this Result) Syslogf(ph *Handle, message string, args ...any) {
	ph.Syslogf(this.SyslogPriority(), message, args...)
}

func (this Result) IsSuccess() bool {
	switch this {
	case ResultSuccess:
		return true
	default:
		return false
	}
}

func (this Result) Errorf(causeType ErrorCauseType, message string, args ...any) *Error {
	if this.IsSuccess() {
		return nil
	}

	msgErr := fmt.Errorf(message, args...)

	return &Error{
		Result:    this,
		CauseType: causeType,
		Message:   msgErr.Error(),
		Cause:     errors.Unwrap(msgErr),
	}
}

func (this Result) ToError(causeType ErrorCauseType) *Error {
	return this.Errorf(causeType, "")
}

type Flag uint64

const (
	// FlagSilent tells the authentication service should not generate any messages.
	FlagSilent = Flag(_PAM_SILENT)

	//////////////////////////////////////////////////////////////////////////////
	// Note: these flags are used by pam_authenticate{,_secondary}()
	//////////////////////////////////////////////////////////////////////////////

	// FlagDisallowNullAuthToken tells the authentication service should return ResultAuthErr if the
	// user has a null authentication token.
	FlagDisallowNullAuthToken = Flag(_PAM_DISALLOW_NULL_AUTHTOK)

	//////////////////////////////////////////////////////////////////////////////
	// Note: these flags are used for pam_setcred()
	//////////////////////////////////////////////////////////////////////////////

	// FlagEstablishCredentials should set user credentials for an authentication service
	FlagEstablishCredentials = Flag(_PAM_ESTABLISH_CRED)
	// FlagDeleteCredentials should delete user credentials associated with an authentication service.
	FlagDeleteCredentials = Flag(_PAM_DELETE_CRED)
	// FlagReinitializeCredentials should reinitialize user credentials.
	FlagReinitializeCredentials = Flag(_PAM_REINITIALIZE_CRED)
	// FlagRefreshCredentials should extend lifetime of user credentials.
	FlagRefreshCredentials = Flag(_PAM_REFRESH_CRED)

	//////////////////////////////////////////////////////////////////////////////
	// Note: these flags are used by pam_chauthtok
	//////////////////////////////////////////////////////////////////////////////

	// FlagChangeExpiredAuthToken tells the password service should only update those passwords that have
	// aged. If this flag is not passed, the password service should update all passwords.
	FlagChangeExpiredAuthToken = Flag(_PAM_CHANGE_EXPIRED_AUTHTOK)
)

func FlagsFromBitMask(in uint64) Flags {
	result := Flags{}
	result.FromBitMask(in)
	return result
}

type Flags []Flag

func (this *Flags) FromBitMask(in uint64) {
	var buf Flags
	if (uint64(FlagSilent) & in) != 0 {
		buf = append(buf, FlagSilent)
	}

	if (uint64(FlagDisallowNullAuthToken) & in) != 0 {
		buf = append(buf, FlagDisallowNullAuthToken)
	}
	if (uint64(FlagEstablishCredentials) & in) != 0 {
		buf = append(buf, FlagEstablishCredentials)
	}
	if (uint64(FlagDeleteCredentials) & in) != 0 {
		buf = append(buf, FlagDeleteCredentials)
	}
	if (uint64(FlagReinitializeCredentials) & in) != 0 {
		buf = append(buf, FlagReinitializeCredentials)
	}
	if (uint64(FlagRefreshCredentials) & in) != 0 {
		buf = append(buf, FlagRefreshCredentials)
	}

	if (uint64(FlagChangeExpiredAuthToken) & in) != 0 {
		buf = append(buf, FlagChangeExpiredAuthToken)
	}

	*this = buf
}

func (this Flags) ToBitMask() uint64 {
	var buf uint64

	for _, v := range this {
		buf |= uint64(v)
	}

	return buf
}

type ItemType uint8

//goland:noinspection GoUnusedConst
const (
	// ItemTypeService represents the service name.
	ItemTypeService = ItemType(_PAM_SERVICE)
	// ItemTypeUsername represents the username.
	ItemTypeUsername = ItemType(_PAM_USER)
	// ItemTypeTty represents the tty name.
	ItemTypeTty = ItemType(_PAM_TTY)
	// ItemTypeRemoteHost represents the remote host name.
	ItemTypeRemoteHost = ItemType(_PAM_RHOST)
	// ItemTypeConv represents the pam_conv structure.
	ItemTypeConv = ItemType(_PAM_CONV)
	// ItemTypeAuthToken represents the authentication token (password).
	ItemTypeAuthToken = ItemType(_PAM_AUTHTOK)
	// ItemTypeOldAuthToken represents the old authentication token.
	ItemTypeOldAuthToken = ItemType(_PAM_OLDAUTHTOK)
	// ItemTypeRemoteUsername represents the remote username.
	ItemTypeRemoteUsername = ItemType(_PAM_RUSER)
	// ItemTypeUserPrompt represents the prompt for getting a username.
	ItemTypeUserPrompt = ItemType(_PAM_USER_PROMPT)

	//////////////////////////////////////////////////////////////////////////////
	// Linux-PAM extensions
	//////////////////////////////////////////////////////////////////////////////

	// ItemTypeFailDelay represents app supplied function to override failure delays.
	ItemTypeFailDelay = ItemType(_PAM_FAIL_DELAY)
	// ItemTypeXDisplay represents the X display name.
	ItemTypeXDisplay = ItemType(_PAM_XDISPLAY)
	// ItemTypeXAuthData represents the X server authentication data.
	ItemTypeXAuthData = ItemType(_PAM_XAUTHDATA)
	// ItemTypeAuthTokenType represents the type for pam_get_authtok.
	ItemTypeAuthTokenType = ItemType(_PAM_AUTHTOK_TYPE)
)
