package service

import (
	"fmt"
	"io"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type remote struct {
	ssh.Context
}

func (this *remote) GetField(name string) (any, bool, error) {
	switch name {
	case "host":
		return this.Host(), true, nil
	case "user":
		return this.User(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *remote) Host() net.Host {
	var result net.Host
	_ = result.SetNetAddr(this.RemoteAddr())
	return result
}

func (this *remote) String() string {
	return this.User() + "@" + this.Host().String()
}

type authorizeRequest struct {
	service *service
	remote  remote
}

func (this *authorizeRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return this.remote, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *authorizeRequest) Context() ssh.Context {
	return this.remote.Context
}

func (this *authorizeRequest) Remote() common.Remote {
	return &this.remote
}

func (this *authorizeRequest) Logger() log.Logger {
	return this.service.logger(this.remote)
}

func (this *authorizeRequest) Sessions() session.Repository {
	return this.service.sessions
}

func (this *authorizeRequest) Validate(auth authorization.Authorization) (bool, error) {
	req := environmentRequest{
		service:       this.service,
		remote:        &this.remote,
		authorization: auth,
	}
	return this.service.environments.WillBeAccepted(&req)
}

type publicKeyAuthorizeRequest struct {
	authorizeRequest
	publicKey gssh.PublicKey
}

func (this *publicKeyAuthorizeRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "publicKey":
		return this.publicKey, true, nil
	default:
		return this.authorizeRequest.GetField(name)
	}
}

func (this *publicKeyAuthorizeRequest) RemotePublicKey() gssh.PublicKey {
	return this.publicKey
}

type passwordAuthorizeRequest struct {
	authorizeRequest
	password string
}

func (this *passwordAuthorizeRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "password":
		return this.password, true, nil
	default:
		return this.authorizeRequest.GetField(name)
	}
}

func (this *passwordAuthorizeRequest) RemotePassword() string {
	return this.password
}

type interactiveAuthorizeRequest struct {
	authorizeRequest
	challenger gssh.KeyboardInteractiveChallenge
}

func (this *interactiveAuthorizeRequest) GetField(name string) (any, bool, error) {
	return this.authorizeRequest.GetField(name)
}

func (this *interactiveAuthorizeRequest) SendInfo(message string) error {
	_, err := this.challenger("", message, nil, nil)
	return err
}

func (this *interactiveAuthorizeRequest) SendError(message string) error {
	_, err := this.challenger("", "Error: "+message, nil, nil)
	return err
}

func (this *interactiveAuthorizeRequest) Prompt(message string, echo bool) (string, error) {
	resp, err := this.challenger("", "", []string{message}, []bool{echo})
	if resp == nil {
		return "", io.ErrUnexpectedEOF
	}
	return resp[0], err
}

type environmentRequest struct {
	service       *service
	remote        *remote
	authorization authorization.Authorization
}

func (this *environmentRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "context":
		return this.remote.Context, true, nil
	case "remote":
		return this.remote, true, nil
	case "authorization":
		return this.authorization, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *environmentRequest) Context() ssh.Context {
	return this.remote.Context
}

func (this *environmentRequest) Remote() common.Remote {
	return this.remote
}

func (this *environmentRequest) Logger() log.Logger {
	return this.service.logger(this.remote)
}

func (this *environmentRequest) Authorization() authorization.Authorization {
	return this.authorization
}

type environmentTask struct {
	environmentRequest
	sshSession ssh.Session
	taskType   environment.TaskType
}

func (this *environmentTask) GetField(name string) (any, bool, error) {
	switch name {
	case "taskType":
		return this.taskType, true, nil
	default:
		return this.environmentRequest.GetField(name)
	}
}

func (this *environmentTask) SshSession() ssh.Session {
	return this.sshSession
}

func (this *environmentTask) TaskType() environment.TaskType {
	return this.taskType
}

func newRememberMeNotificationContext(ctx ssh.Context, auth authorization.Authorization, newSession bool, pub ssh.PublicKey) *rememberMeNotificationContext {
	return &rememberMeNotificationContext{
		ctx,
		newSession,
		auth,
		pub,
	}
}

type contextEnabled interface {
	Context() ssh.Context
}

type rememberMeNotificationContext struct {
	context       ssh.Context
	newSession    bool
	authorization authorization.Authorization
	key           ssh.PublicKey
}

func (this *rememberMeNotificationContext) Context() ssh.Context {
	return this.context
}

func (this *rememberMeNotificationContext) GetField(name string, ctx contextEnabled) (any, bool, error) {
	switch name {
	case "authorization":
		return this.authorization, true, nil
	case "key":
		return this.key, true, nil
	case "session":
		sess := this.authorization.FindSession()
		if sess == nil {
			return nil, true, nil
		}
		si, err := sess.Info(ctx.Context())
		if err != nil {
			return nil, false, err
		}
		return &sessionContext{si, this.newSession}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type sessionContext struct {
	session.Info
	isNew bool
}

func (this *sessionContext) GetField(name string) (any, bool, error) {
	switch name {
	case "new":
		return this.isNew, true, nil
	default:
		return nil, false, nil
	}
}

type connectionContext struct {
	Context ssh.Context
}

func (this *connectionContext) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return remote{this.Context}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}
