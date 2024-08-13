package service

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"io"
)

type remote struct {
	ssh.Context
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

func (this *authorizeRequest) Context() ssh.Context {
	return this.remote.Context
}

func (this *authorizeRequest) Remote() common.Remote {
	return &this.remote
}

func (this *authorizeRequest) Logger() log.Logger {
	return this.service.logger(this.remote)
}

func (this *authorizeRequest) Validate(auth authorization.Authorization) (bool, error) {
	req := environmentRequest{
		service:       this.service,
		remote:        &this.remote,
		authorization: auth,
	}
	return this.service.environment.WillBeAccepted(&req)
}

type sessionAuthorizeRequest struct {
	authorizeRequest
	session session.Session
}

func (this *sessionAuthorizeRequest) Session() session.Session {
	return this.session
}

type publicKeyAuthorizeRequest struct {
	authorizeRequest
	publicKey gssh.PublicKey
}

func (this *publicKeyAuthorizeRequest) RemotePublicKey() gssh.PublicKey {
	return this.publicKey
}

type passwordAuthorizeRequest struct {
	authorizeRequest
	password string
}

func (this *passwordAuthorizeRequest) RemotePassword() string {
	return this.password
}

type interactiveAuthorizeRequest struct {
	authorizeRequest
	challenger gssh.KeyboardInteractiveChallenge
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
	session       session.Session
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

func (this *environmentRequest) FindSession() session.Session {
	return this.session
}

type environmentTask struct {
	environmentRequest
	sshSession ssh.Session
	taskType   environment.TaskType
}

func (this *environmentTask) SshSession() ssh.Session {
	return this.sshSession
}

func (this *environmentTask) TaskType() environment.TaskType {
	return this.taskType
}

type rememberMeNotificationContext struct {
	Authorization authorization.Authorization
	Session       rememberMeNotificationContextSession
	Key           ssh.PublicKey
}

type rememberMeNotificationContextSession struct {
	session.Session
	New bool
}
