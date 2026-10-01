//go:build darwin && !without_pam

package authorization

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"

	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	darwinPamSuccess             int32 = 0
	darwinPamSystemErr           int32 = 4
	darwinPamBufErr              int32 = 5
	darwinPamConvErr             int32 = 6
	darwinPamPermDenied          int32 = 7
	darwinPamMaxtries            int32 = 8
	darwinPamAuthErr             int32 = 9
	darwinPamNewAuthtokReqd      int32 = 10
	darwinPamCredInsufficient    int32 = 11
	darwinPamAuthinfoUnavail     int32 = 12
	darwinPamUserUnknown         int32 = 13
	darwinPamCredUnavail         int32 = 14
	darwinPamCredExpired         int32 = 15
	darwinPamAcctExpired         int32 = 17
	darwinPamAuthtokExpired      int32 = 18
	darwinPamIgnore              int32 = 25
	darwinPamTryAgain            int32 = 27
	darwinPamAppleAcctTempLock   int32 = 1024
	darwinPamAppleAcctLocked     int32 = 1025
	darwinPamPromptEchoOff       int32 = 1
	darwinPamPromptEchoOn        int32 = 2
	darwinPamErrorMsg            int32 = 3
	darwinPamTextInfo            int32 = 4
	darwinPamUser                int32 = 2
	darwinPamRhost               int32 = 4
	darwinPamSilent              int32 = -1 << 31
	darwinPamMaximumMessages           = 32
	darwinPamMaximumMessageSize        = 512
	darwinPamMaximumResponseSize       = 512
)

type darwinPamAPI struct {
	pamStart        func(string, *byte, *darwinPamConversationDescriptor, *uintptr) int32
	pamEnd          func(uintptr, int32) int32
	pamSetItem      func(uintptr, int32, string) int32
	pamAuthenticate func(uintptr, int32) int32
	pamAcctMgmt     func(uintptr, int32) int32
	pamGetItem      func(uintptr, int32, *uintptr) int32
	pamGetenvlist   func(uintptr) uintptr
	pamStrerror     func(uintptr, int32) string
	calloc          func(uintptr, uintptr) uintptr
	free            func(uintptr)
	strnlen         func(uintptr, uintptr) uintptr
}

type darwinPamConversationDescriptor struct {
	Callback uintptr
	AppData  uintptr
}

type darwinPamMessage struct {
	Style   int32
	Padding uint32
	Message uintptr
}

type darwinPamResponse struct {
	Response   uintptr
	ReturnCode int32
	Padding    uint32
}

type darwinPamError struct {
	code    int32
	message string
}

func (this *darwinPamError) Error() string {
	if this.message != "" {
		return this.message
	}
	return fmt.Sprintf("PAM error %d", this.code)
}

var (
	darwinPamLoadOnce sync.Once
	darwinPamLoaded   *darwinPamAPI
	darwinPamLoadErr  error

	darwinPamConversationPointer = purego.NewCallback(darwinPamConversation)
	darwinPamHandlers            sync.Map
	darwinPamNextHandlerID       atomic.Uintptr
)

func loadDarwinPam() (*darwinPamAPI, error) {
	darwinPamLoadOnce.Do(func() {
		pamHandle, err := purego.Dlopen("/usr/lib/libpam.2.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinPamLoadErr = fmt.Errorf("cannot load system PAM: %w", err)
			return
		}
		libcHandle, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			darwinPamLoadErr = fmt.Errorf("cannot load system C library: %w", err)
			return
		}

		api := &darwinPamAPI{}
		for _, binding := range []struct {
			handle uintptr
			name   string
			target any
		}{
			{pamHandle, "pam_start", &api.pamStart},
			{pamHandle, "pam_end", &api.pamEnd},
			{pamHandle, "pam_set_item", &api.pamSetItem},
			{pamHandle, "pam_authenticate", &api.pamAuthenticate},
			{pamHandle, "pam_acct_mgmt", &api.pamAcctMgmt},
			{pamHandle, "pam_get_item", &api.pamGetItem},
			{pamHandle, "pam_getenvlist", &api.pamGetenvlist},
			{pamHandle, "pam_strerror", &api.pamStrerror},
			{libcHandle, "calloc", &api.calloc},
			{libcHandle, "free", &api.free},
			{libcHandle, "strnlen", &api.strnlen},
		} {
			symbol, err := purego.Dlsym(binding.handle, binding.name)
			if err != nil || symbol == 0 {
				if err == nil {
					err = fmt.Errorf("symbol was not found")
				}
				darwinPamLoadErr = fmt.Errorf("cannot resolve %s: %w", binding.name, err)
				return
			}
			purego.RegisterFunc(binding.target, symbol)
		}
		darwinPamLoaded = api
	})
	return darwinPamLoaded, darwinPamLoadErr
}

type darwinPamTransaction struct {
	api       *darwinPamAPI
	handle    uintptr
	handlerID uintptr
	handler   func(int32, string) (string, error)
	status    int32

	mutex       sync.Mutex
	callbackErr error
}

func startDarwinPamTransaction(service, username string, handler func(int32, string) (string, error)) (*darwinPamTransaction, error) {
	api, err := loadDarwinPam()
	if err != nil {
		return nil, err
	}
	t := &darwinPamTransaction{api: api, handler: handler}
	t.handlerID = darwinPamNextHandlerID.Add(1)
	if t.handlerID == 0 {
		t.handlerID = darwinPamNextHandlerID.Add(1)
	}
	darwinPamHandlers.Store(t.handlerID, t)
	conversation := darwinPamConversationDescriptor{Callback: darwinPamConversationPointer, AppData: t.handlerID}
	var usernamePointer uintptr
	if username != "" {
		usernamePointer = api.calloc(uintptr(len(username)+1), 1)
		if usernamePointer == 0 {
			darwinPamHandlers.Delete(t.handlerID)
			return nil, t.errorFor(darwinPamBufErr)
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(usernamePointer)), len(username)+1), username)
		defer api.free(usernamePointer)
	}
	status := api.pamStart(service, (*byte)(unsafe.Pointer(usernamePointer)), &conversation, &t.handle)
	if status != darwinPamSuccess {
		darwinPamHandlers.Delete(t.handlerID)
		return nil, t.errorFor(status)
	}
	return t, nil
}

func (this *darwinPamTransaction) errorFor(status int32) error {
	message := ""
	if this.api != nil && this.api.pamStrerror != nil {
		message = this.api.pamStrerror(this.handle, status)
	}
	return &darwinPamError{code: status, message: message}
}

func (this *darwinPamTransaction) call(operation func() int32) error {
	status := operation()
	this.status = status
	this.mutex.Lock()
	callbackErr := this.callbackErr
	this.callbackErr = nil
	this.mutex.Unlock()
	if callbackErr != nil {
		return callbackErr
	}
	if status != darwinPamSuccess {
		return this.errorFor(status)
	}
	return nil
}

func (this *darwinPamTransaction) setCallbackError(err error) {
	this.mutex.Lock()
	this.callbackErr = err
	this.mutex.Unlock()
}

func (this *darwinPamTransaction) SetItem(item int32, value string) error {
	return this.call(func() int32 { return this.api.pamSetItem(this.handle, item, value) })
}

func (this *darwinPamTransaction) Authenticate(flags int32) error {
	return this.call(func() int32 { return this.api.pamAuthenticate(this.handle, flags) })
}

func (this *darwinPamTransaction) AcctMgmt(flags int32) error {
	return this.call(func() int32 { return this.api.pamAcctMgmt(this.handle, flags) })
}

func (this *darwinPamTransaction) GetItem(item int32) (string, error) {
	var value uintptr
	if err := this.call(func() int32 { return this.api.pamGetItem(this.handle, item, &value) }); err != nil {
		return "", err
	}
	if value == 0 {
		return "", nil
	}
	return darwinPamCStringUnbounded(this.api, value)
}

func (this *darwinPamTransaction) GetEnvList() (map[string]string, error) {
	list := this.api.pamGetenvlist(this.handle)
	if list == 0 {
		this.status = darwinPamBufErr
		return nil, this.errorFor(darwinPamBufErr)
	}
	this.status = darwinPamSuccess
	defer this.api.free(list)

	result := sys.EnvVars{}
	pointerSize := unsafe.Sizeof(uintptr(0))
	for i := uintptr(0); ; i++ {
		pointer := *(*uintptr)(unsafe.Pointer(list + i*pointerSize))
		if pointer == 0 {
			return result, nil
		}
		value, err := darwinPamCStringUnbounded(this.api, pointer)
		this.api.free(pointer)
		if err != nil {
			for j := i + 1; ; j++ {
				remaining := *(*uintptr)(unsafe.Pointer(list + j*pointerSize))
				if remaining == 0 {
					break
				}
				this.api.free(remaining)
			}
			return nil, err
		}
		if key, value, ok := strings.Cut(value, "="); ok {
			result[key] = value
		}
	}
}

func (this *darwinPamTransaction) End() error {
	this.mutex.Lock()
	handle := this.handle
	this.handle = 0
	this.mutex.Unlock()
	if handle == 0 {
		return nil
	}
	status := this.api.pamEnd(handle, this.status)
	darwinPamHandlers.Delete(this.handlerID)
	if status != darwinPamSuccess {
		return this.errorFor(status)
	}
	return nil
}

func darwinPamConversation(numMessages int32, messages uintptr, responses *uintptr, appData uintptr) (result int32) {
	result = darwinPamConvErr
	defer func() {
		if recover() != nil {
			result = darwinPamConvErr
		}
	}()
	if responses == nil {
		return result
	}
	*responses = 0
	if numMessages <= 0 || numMessages > darwinPamMaximumMessages || messages == 0 {
		return result
	}
	value, ok := darwinPamHandlers.Load(appData)
	if !ok {
		return result
	}
	transaction := value.(*darwinPamTransaction)
	api := transaction.api
	responseSize := unsafe.Sizeof(darwinPamResponse{})
	responsePointer := api.calloc(uintptr(numMessages), responseSize)
	if responsePointer == 0 {
		return darwinPamBufErr
	}
	responseValues := unsafe.Slice((*darwinPamResponse)(unsafe.Pointer(responsePointer)), int(numMessages))
	success := false
	defer func() {
		if success {
			return
		}
		for i := range responseValues {
			if responseValues[i].Response != 0 {
				darwinPamScrubAndFree(api, responseValues[i].Response, darwinPamMaximumResponseSize+1)
			}
		}
		api.free(responsePointer)
	}()

	messagePointers := unsafe.Slice((*uintptr)(unsafe.Pointer(messages)), int(numMessages))
	for i, messagePointer := range messagePointers {
		if messagePointer == 0 {
			return darwinPamConvErr
		}
		message := (*darwinPamMessage)(unsafe.Pointer(messagePointer))
		text, err := darwinPamCString(api, message.Message, darwinPamMaximumMessageSize)
		if err != nil {
			return darwinPamConvErr
		}
		response, err := transaction.handler(message.Style, text)
		if err != nil {
			transaction.setCallbackError(err)
			return darwinPamConvErr
		}
		if message.Style != darwinPamPromptEchoOff && message.Style != darwinPamPromptEchoOn {
			continue
		}
		if len(response) > darwinPamMaximumResponseSize {
			transaction.setCallbackError(fmt.Errorf("PAM response exceeds %d bytes", darwinPamMaximumResponseSize))
			return darwinPamConvErr
		}
		allocated := api.calloc(uintptr(len(response)+1), 1)
		if allocated == 0 {
			return darwinPamBufErr
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(allocated)), len(response)+1), response)
		responseValues[i].Response = allocated
	}

	*responses = responsePointer
	success = true
	return darwinPamSuccess
}

func darwinPamCString(api *darwinPamAPI, pointer uintptr, maximum uintptr) (string, error) {
	if pointer == 0 {
		return "", nil
	}
	length := api.strnlen(pointer, maximum)
	if length == maximum {
		return "", fmt.Errorf("PAM string exceeds %d bytes", maximum)
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length))), nil
}

func darwinPamCStringUnbounded(api *darwinPamAPI, pointer uintptr) (string, error) {
	if pointer == 0 {
		return "", nil
	}
	length := api.strnlen(pointer, ^uintptr(0))
	maximumInt := uintptr(^uint(0) >> 1)
	if length > maximumInt {
		return "", fmt.Errorf("PAM string is too large")
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length))), nil
}

func darwinPamScrubAndFree(api *darwinPamAPI, pointer uintptr, maximum int) {
	if pointer == 0 {
		return
	}
	length := api.strnlen(pointer, uintptr(maximum))
	if length < uintptr(maximum) {
		clear(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length)))
	}
	api.free(pointer)
}

func (this *LocalAuthorizer) checkPassword(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if this.conf.PamService == "" {
		return "", nil, false, berrors.Config.Newf("configuration parameter pamService must not be empty for local password authentication on Darwin")
	}
	handler := func(style int32, _ string) (string, error) {
		switch style {
		case darwinPamPromptEchoOff, darwinPamPromptEchoOn:
			password := req.RemotePassword()
			accepted, err := validatePassword(password, req)
			if err != nil {
				return "", err
			}
			if !accepted {
				return "", &darwinPamError{code: darwinPamCredInsufficient}
			}
			return password, nil
		case darwinPamErrorMsg:
			return "", errors.New("error messages are not supported when just checking password")
		case darwinPamTextInfo:
			return "", errors.New("info messages are not supported when just checking password")
		default:
			return "", errors.New("unrecognized message style")
		}
	}
	return authorizeWithDarwinPam(this.conf.PamService, requestedUsername, req.Connection().Remote().Host().String(), false, handler)
}

func (this *LocalAuthorizer) checkInteractive(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	if this.conf.PamService == "" {
		return "", nil, false, berrors.Config.Newf("configuration parameter pamService must not be empty for local keyboard-interactive authentication on Darwin")
	}
	handler := func(style int32, message string) (string, error) {
		var response string
		var err error
		switch style {
		case darwinPamPromptEchoOff:
			response, err = req.Prompt(message, false)
		case darwinPamPromptEchoOn:
			response, err = req.Prompt(message, true)
		case darwinPamErrorMsg:
			return "", req.SendError(message)
		case darwinPamTextInfo:
			return "", req.SendInfo(message)
		default:
			return "", errors.New("unrecognized message style")
		}
		if err != nil {
			return "", err
		}
		accepted, err := validatePassword(response, req)
		if err != nil {
			return "", err
		}
		if !accepted {
			return "", &darwinPamError{code: darwinPamCredInsufficient}
		}
		return response, nil
	}
	return authorizeWithDarwinPam(this.conf.PamService, requestedUsername, req.Connection().Remote().Host().String(), true, handler)
}

func authorizeWithDarwinPam(service, requestedUsername, remoteHost string, interactive bool, handler func(int32, string) (string, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	accountPhase := false
	conversation := func(style int32, message string) (string, error) {
		if !accountPhase {
			return handler(style, message)
		}
		switch style {
		case darwinPamErrorMsg, darwinPamTextInfo:
			if interactive {
				return handler(style, message)
			}
			return "", nil
		case darwinPamPromptEchoOff, darwinPamPromptEchoOn:
			return "", errors.New("PAM account management requested an unsupported prompt")
		default:
			return "", errors.New("unrecognized message style")
		}
	}
	t, err := startDarwinPamTransaction(service, requestedUsername, conversation)
	if err != nil {
		return "", nil, false, berrors.System.Newf("cannot start PAM transaction: %w", err)
	}
	defer func() {
		if err := t.End(); err != nil {
			rErr = errors.Join(rErr, berrors.System.Newf("cannot end PAM transaction: %w", err))
			success = false
		}
	}()

	if err := t.SetItem(darwinPamRhost, remoteHost); err != nil {
		return "", nil, false, berrors.System.Newf("cannot set PAM_RHOST: %w", err)
	}
	flags := int32(0)
	if !interactive {
		flags = darwinPamSilent
	}
	if err := t.Authenticate(flags); err != nil {
		if isDarwinPamDenial(err) {
			return "", nil, false, nil
		}
		return "", nil, false, berrors.System.Newf("PAM authentication failed: %w", err)
	}
	accountPhase = true
	if err := t.AcctMgmt(flags); err != nil {
		if isDarwinPamDenial(err) {
			return "", nil, false, nil
		}
		return "", nil, false, berrors.System.Newf("PAM account management failed: %w", err)
	}
	username, err = t.GetItem(darwinPamUser)
	if err != nil {
		return "", nil, false, berrors.System.Newf("cannot get PAM_USER: %w", err)
	}
	env, err = t.GetEnvList()
	if err != nil {
		return "", nil, false, berrors.System.Newf("cannot get PAM environment: %w", err)
	}
	return username, env, true, nil
}

func isDarwinPamDenial(err error) bool {
	var pamErr *darwinPamError
	if !errors.As(err, &pamErr) {
		return false
	}
	switch pamErr.code {
	case darwinPamPermDenied, darwinPamAuthErr, darwinPamCredInsufficient, darwinPamAuthinfoUnavail,
		darwinPamUserUnknown, darwinPamMaxtries, darwinPamNewAuthtokReqd, darwinPamAcctExpired,
		darwinPamCredUnavail, darwinPamCredExpired, darwinPamTryAgain, darwinPamIgnore,
		darwinPamAuthtokExpired, darwinPamAppleAcctTempLock, darwinPamAppleAcctLocked:
		return true
	default:
		return false
	}
}
