package service

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/yasshd/pkg/authorization"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/engity-com/yasshd/pkg/environment"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"net"
)

type remote struct {
	ssh.Context
}

func (this *remote) Addr() net.Addr {
	return this.RemoteAddr()
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

type environmentRequest struct {
	service       *service
	remote        *remote
	authorization authorization.Authorization
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
	session  ssh.Session
	taskType environment.TaskType
}

func (this *environmentTask) Session() ssh.Session {
	return this.session
}

func (this *environmentTask) TaskType() environment.TaskType {
	return this.taskType
}
