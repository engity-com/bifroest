package core

import (
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/engity/pam-oidc/pkg/user"
	"golang.org/x/oauth2"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const (
	DefaultSocketPath = "/var/run/pam-oidc.sock"
)

type Service struct {
	Configurations ConfigurationProvider

	SocketPerm  os.FileMode
	SocketPath  string
	SocketUser  *user.User
	SocketGroup *user.Group
}

func (this *Service) handle(conn *net.UnixConn) (string, error) {
	var client string
	fail := func(err error) (string, error) {
		return client, err
	}

	run, ck, cl, err := ReadCommandHeader(conn)
	if err != nil {
		return fail(err)
	}
	client = cl

	l := log.With("remote.username", run).
		With("config", ck).
		With("config", ck).
		With("client", cl)

	l.Debug("client connected")

	cs := NewCommandSender(conn)

	conf, err := this.Configurations.Get(ck)
	if err != nil {
		return fail(err)
	}
	if conf == nil {
		return client, cs.FailedResultf(ResultConfigurationErr, nil, "illegal configuration requested by client: %v", ck)
	}

	cord, err := this.newCoordinator(conf, cs)
	if err != nil {
		return client, cs.FailedResultf(ResultSystemErr, nil, "illegal configuration requested by client: %v", ck)
	}

	lu, result, err := cord.Run(nil, run)
	if err != nil {
		return fail(err)
	}

	if result.IsSuccess() {
		return client, cs.SuccessResult(result, lu.Name, lu.Uid, lu.Group.Name, lu.Group.Gid)
	} else {
		return client, cs.FailedResult(result, err)
	}
}

func (this *Service) newCoordinator(conf *Configuration, cs *CommandSender) (*Coordinator, error) {
	fail := func(err error) (*Coordinator, error) {
		return nil, err
	}

	cord, err := NewCoordinator(conf)
	if err != nil {
		return fail(err)
	}

	cord.OnDeviceAuthStarted = func(dar *oauth2.DeviceAuthResponse) error {
		if v := dar.VerificationURIComplete; v != "" {
			cs.MustInfof("Open %s in your browser and approve the login request. Waiting for approval...", v)
			cs.MustLogf(level.Debug, "showing request to open %s in user's browser", v)
		} else {
			cs.MustInfof("Open %s in your browser and enter the code %s. Waiting for approval...", dar.VerificationURI, dar.UserCode)
			cs.MustLogf(level.Debug, "showing request to open %s in user's browser using code %s", dar.VerificationURI, dar.UserCode)
		}
		return nil
	}

	cord.OnTokenReceived = func(*oauth2.Token) error {
		cs.MustLogf(level.Debug, "token received")
		return nil
	}

	cord.OnIdTokenReceived = func(v *oidc.IDToken) error {
		cs.MustLogf(level.Debug, "id token received (issuer=%q, subject=%q)", v.Issuer, v.Subject)
		return nil
	}

	cord.OnUserInfoReceived = func(v *oidc.UserInfo) error {
		cs.MustLogf(level.Debug, "user info received (subject=%q, email=%q)", v.Subject, v.Email)
		return nil
	}

	return cord, nil
}

func (this *Service) runHandle(conn *net.UnixConn) {
	defer func() {
		_ = conn.Close()
	}()

	var l log.Logger
	client, err := this.handle(conn)
	if client != "" {
		l = log.With("client", client)
	} else {
		l = log.With("client", conn.RemoteAddr())
	}
	if err != nil {
		l := l.
			WithError(err).
			With("socket", this.SocketPath)

		if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
			l.Debug("client unexpected disconnected")
		} else if errors.Is(err, ErrIllegalCommandHeaderIntroduction) {
			l.Debug("there was a connection to the socket which does not meet the protocol; it was rejected")
		} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			l.Warn("unexpected client disconnected")
		} else {
			l.Error("unexpected error while handling client")
		}
	} else {
		l.Debug("client disconnected")
	}
}

func (this *Service) Run() error {
	fail := func(err error) error {
		return fmt.Errorf("run of service failed: %w", err)
	}

	ln, err := this.listenToSocket()
	if err != nil {
		return fail(err)
	}
	defer func() {
		_ = ln.Close()
	}()

	log.With("socket", this.SocketPath).
		Info("listening for clients...")
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return fail(err)
		}
		go this.runHandle(conn)
	}
}

func (this *Service) listenToSocket() (*net.UnixListener, error) {
	fail := func(err error) (*net.UnixListener, error) {
		return nil, err
	}
	failf := func(message string, args ...any) (*net.UnixListener, error) {
		return fail(fmt.Errorf(message, args...))
	}

	_ = os.MkdirAll(filepath.Dir(this.SocketPath), 0700)
	_ = os.Remove(this.SocketPath)

	ln, err := net.ListenUnix("unix", &net.UnixAddr{this.SocketPath, "unix"})
	if err != nil {
		return failf("cannot listen to socket path %q: %w", this.SocketPath, err)
	}

	u := this.SocketUser
	g := this.SocketGroup
	if u != nil || g != nil {
		if u == nil {
			if u, err = user.LookupUid(uint64(os.Getuid())); err != nil {
				return failf("cannot resolve current user (%d): %w", os.Getuid(), err)
			}
		}
		if g == nil {
			if g, err = user.LookupGid(uint64(os.Getgid())); err != nil {
				return failf("cannot resolve current group (%d): %w", os.Getgid(), err)
			}
		}
		if err := os.Chown(this.SocketPath, int(u.Uid), int(u.Group.Gid)); err != nil {
			return failf("cannot change ownership of %q to %v:%v: %w", this.SocketPath, u, g, err)
		}
	}

	if v := this.SocketPerm; v > 0 {
		if err := os.Chmod(this.SocketPath, v); err != nil {
			return failf("cannot change permissions of %q to %v: %w", this.SocketPath, v, err)
		}
	}

	ln.SetUnlinkOnClose(true)

	return ln, nil
}
