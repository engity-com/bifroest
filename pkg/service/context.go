package service

import (
	"fmt"
	"io"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type remote struct {
	glssh.Context
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
	service    *service
	connection *connection
}

func (this *authorizeRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "connection":
		return this.connection, true, nil
	case "remote":
		return this.connection.Remote(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *authorizeRequest) Context() glssh.Context {
	return this.connection.context
}

func (this *authorizeRequest) Connection() bconn.Connection {
	return this.connection
}

func (this *authorizeRequest) Sessions() session.Repository {
	return this.service.sessions
}

func (this *authorizeRequest) Validate(auth authorization.Authorization) (bool, error) {
	ctx := environmentContext{
		service:       this.service,
		connection:    this.connection,
		authorization: auth,
	}
	return this.service.environments.WillBeAccepted(&ctx)
}

type publicKeyAuthorizeRequest struct {
	authorizeRequest
	publicKey gossh.PublicKey
}

func (this *publicKeyAuthorizeRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "publicKey":
		return this.publicKey, true, nil
	default:
		return this.authorizeRequest.GetField(name)
	}
}

func (this *publicKeyAuthorizeRequest) RemotePublicKey() gossh.PublicKey {
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
	challenger gossh.KeyboardInteractiveChallenge
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

type environmentContext struct {
	service       *service
	connection    *connection
	authorization authorization.Authorization
}

func (this *environmentContext) GetField(name string) (any, bool, error) {
	switch name {
	case "context":
		return this.connection.context, true, nil
	case "connection":
		return this.connection, true, nil
	case "remote":
		return this.connection.Remote(), true, nil
	case "authorization":
		return this.authorization, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *environmentContext) Context() glssh.Context {
	return this.connection.context
}

func (this *environmentContext) Connection() bconn.Connection {
	return this.connection
}

func (this *environmentContext) Authorization() authorization.Authorization {
	return this.authorization
}

type environmentRequest struct {
	environmentContext
	reportWriter io.Writer
}

func (this *environmentRequest) StartPreparation(id, title string, attrs environment.PreparationProgressAttributes) (environment.PreparationProgress, error) {
	flowStr := this.authorization.Flow().String()

	for _, candidate := range this.service.Configuration.Ssh.PreparationMessages {
		if !candidate.Flow.MatchString(flowStr) {
			continue
		}
		if !candidate.Id.MatchString(id) {
			continue
		}
		result := &environmentRequestPreparationProgress{this, id, title, attrs, &candidate}
		if err := result.printStart(); err != nil {
			return nil, err
		}
		return result, nil
	}

	return nil, nil
}

type environmentRequestPreparationProgress struct {
	*environmentRequest
	id    string
	title string
	attrs environment.PreparationProgressAttributes
	pm    *configuration.PreparationMessage
}

func (this *environmentRequestPreparationProgress) GetField(name string) (any, bool, error) {
	switch name {
	case "id":
		return this.id, true, nil
	case "title":
		return this.title, true, nil
	default:
		if this.attrs != nil {
			v, ok := this.attrs[name]
			if ok {
				return v, true, nil
			}
		}
		return this.environmentRequest.GetField(name)
	}
}

func (this *environmentRequestPreparationProgress) print(tmpl *template.String, data any) error {
	w := this.reportWriter
	if w == nil {
		return nil
	}
	v, err := tmpl.Render(data)
	if err != nil {
		return errors.Network.Newf("cannot render preparation progress message for client: %w", err)
	}
	if v == "" {
		return nil
	}
	_, err = w.Write([]byte(v))
	if err != nil {
		return errors.Network.Newf("cannot print preparation progress message to client: %w", err)
	}
	return nil
}

func (this *environmentRequestPreparationProgress) printStart() error {
	return this.print(&this.pm.Start, this)
}

func (this *environmentRequestPreparationProgress) Report(progress float32) error {
	return this.print(&this.pm.Update, environmentRequestPreparationProgressProgress{this, progress})
}

func (this *environmentRequestPreparationProgress) Done() error {
	return this.print(&this.pm.End, this)
}

func (this *environmentRequestPreparationProgress) Error(err error) error {
	return this.print(&this.pm.Error, environmentRequestPreparationProgressError{this, err})
}

type environmentRequestPreparationProgressProgress struct {
	*environmentRequestPreparationProgress
	progress float32
}

func (this environmentRequestPreparationProgressProgress) GetField(name string) (any, bool, error) {
	switch name {
	case "progress":
		return this.progress, true, nil
	case "percentage":
		return this.progress * 100.0, true, nil
	default:
		return this.environmentRequestPreparationProgress.GetField(name)
	}
}

type environmentRequestPreparationProgressError struct {
	*environmentRequestPreparationProgress
	error error
}

func (this environmentRequestPreparationProgressError) GetField(name string) (any, bool, error) {
	switch name {
	case "error":
		return this.error, true, nil
	default:
		return this.environmentRequestPreparationProgress.GetField(name)
	}
}

type environmentTask struct {
	environmentContext
	sshSession glssh.Session
	taskType   environment.TaskType
}

func (this *environmentTask) GetField(name string) (any, bool, error) {
	switch name {
	case "taskType":
		return this.taskType, true, nil
	default:
		return this.environmentContext.GetField(name)
	}
}

func (this *environmentTask) SshSession() glssh.Session {
	return this.sshSession
}

func (this *environmentTask) TaskType() environment.TaskType {
	return this.taskType
}

func newRememberMeNotificationContext(ctx glssh.Context, auth authorization.Authorization, newSession bool, pub glssh.PublicKey) *rememberMeNotificationContext {
	return &rememberMeNotificationContext{
		ctx,
		newSession,
		auth,
		pub,
	}
}

type contextEnabled interface {
	Context() glssh.Context
}

type rememberMeNotificationContext struct {
	context       glssh.Context
	newSession    bool
	authorization authorization.Authorization
	key           glssh.PublicKey
}

func (this *rememberMeNotificationContext) Context() glssh.Context {
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
	Context glssh.Context
}

func (this *connectionContext) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return remote{this.Context}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type noopContext struct {
}
