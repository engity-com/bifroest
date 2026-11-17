//go:build darwin && !without_pam

package authorization

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type darwinPamTransactionLike interface {
	Authenticate(int32) error
	AcctMgmt(int32) error
	SetItem(int32, string) error
	GetItem(int32) (string, error)
	GetEnvList() (map[string]string, error)
	End() error
}

type darwinPamStart func(string, string, func(int32, string) (string, error)) (darwinPamTransactionLike, error)

func startDarwinPam(service, username string, handler func(int32, string) (string, error)) (darwinPamTransactionLike, error) {
	return startDarwinPamTransaction(service, username, handler)
}

type darwinPamOptions struct {
	Context                                 context.Context
	Service, Username, RemoteHost           string
	Authenticate, Interactive, DisallowNull bool
}

// Both modes are synchronous and thread-affine. The account-only mode is a
// primitive, not a resume authorization: fresh native account/target checks and
// explicit operator opt-in remain mandatory before it can grant any access.
func authorizeWithDarwinPam(options darwinPamOptions, handler func(int32, string) (string, error), start darwinPamStart) (username string, env sys.EnvVars, success bool, resultErr error) {
	fail := func(err error) (string, sys.EnvVars, bool, error) {
		return "", nil, false, berrors.System.Newf("darwin PAM transaction failed: %w", err)
	}
	if options.Context == nil || start == nil || options.Service == "" || strings.ContainsRune(options.Service+options.Username+options.RemoteHost, 0) || (!options.Authenticate && options.Username == "") || (options.Authenticate && handler == nil) {
		return fail(fmt.Errorf("invalid Darwin PAM transaction input"))
	}
	if err := options.Context.Err(); err != nil {
		return fail(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	accountPhase := !options.Authenticate
	var callbackErr error
	var conversationMutex sync.Mutex
	callbackError := func() error { conversationMutex.Lock(); defer conversationMutex.Unlock(); return callbackErr }
	accountMessages, accountBytes := 0, 0
	conversation := func(style int32, message string) (string, error) {
		conversationMutex.Lock()
		defer conversationMutex.Unlock()
		if callbackErr != nil {
			return "", callbackErr
		}
		deny := func(err error) (string, error) { callbackErr = err; return "", err }
		if err := options.Context.Err(); err != nil {
			return deny(err)
		}
		if !accountPhase {
			return handler(style, message)
		}
		accountMessages++
		accountBytes += len(message)
		if accountMessages > darwinPamMaximumMessages || len(message) > darwinPamMaximumMessageSize || accountBytes > 32<<10 {
			return deny(fmt.Errorf("darwin PAM account conversation exceeds its bounds"))
		}
		switch style {
		case darwinPamErrorMsg, darwinPamTextInfo:
			if options.Authenticate && options.Interactive {
				return handler(style, message)
			}
			return "", nil
		default:
			return deny(fmt.Errorf("darwin PAM account management requires an unsupported conversation: %w", ErrSessionResumeDenied))
		}
	}
	transaction, err := start(options.Service, options.Username, conversation)
	if err != nil {
		return fail(err)
	}
	if transaction == nil {
		return fail(fmt.Errorf("darwin PAM returned no transaction"))
	}
	defer func() {
		endErr := transaction.End()
		if endErr != nil {
			endErr = berrors.System.Newf("cannot end PAM transaction: %w", endErr)
		}
		resultErr = errors.Join(resultErr, endErr, options.Context.Err(), callbackError())
		if resultErr != nil {
			username, env, success = "", nil, false
		}
	}()
	check := func(operation func() error) error {
		if err := options.Context.Err(); err != nil {
			return err
		}
		if err := callbackError(); err != nil {
			return err
		}
		err := operation()
		return errors.Join(err, options.Context.Err(), callbackError())
	}
	if err := check(func() error { return transaction.SetItem(darwinPamRhost, options.RemoteHost) }); err != nil {
		return fail(err)
	}
	flags := int32(0)
	if !options.Interactive {
		flags = darwinPamSilent
	}
	if options.DisallowNull {
		flags |= darwinPamDisallowNullAuthtok
	}
	if options.Authenticate {
		if err := check(func() error { return transaction.Authenticate(flags) }); err != nil {
			if isDarwinPamDenial(err) {
				return "", nil, false, nil
			}
			return fail(err)
		}
	}
	conversationMutex.Lock()
	accountPhase = true
	conversationMutex.Unlock()
	if err := check(func() error { return transaction.AcctMgmt(flags) }); err != nil {
		if isDarwinPamDenial(err) {
			return "", nil, false, nil
		}
		return fail(err)
	}
	if err := check(func() error { var err error; username, err = transaction.GetItem(darwinPamUser); return err }); err != nil {
		return fail(err)
	}
	if username == "" {
		return fail(fmt.Errorf("darwin PAM returned an empty account identity"))
	}
	if err := check(func() error { var err error; env, err = transaction.GetEnvList(); return err }); err != nil {
		return fail(err)
	}
	return username, env, true, nil
}
