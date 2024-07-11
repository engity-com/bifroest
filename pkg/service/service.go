package service

import (
	"errors"
	"fmt"
	"github.com/creack/pty"
	log "github.com/echocat/slf4g"
	"github.com/engity/pam-oidc/pkg/configuration"
	"github.com/engity/pam-oidc/pkg/crypto"
	"github.com/engity/pam-oidc/pkg/user"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

type Service struct {
	Configuration configuration.Configuration
}

func (this *Service) Run() error {
	svc, err := this.prepare()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	for _, addr := range this.Configuration.Ssh.Address {
		ln, err := addr.Listen()
		if err != nil {
			// TODO! Stop the other already started listeners...
			return fmt.Errorf("cannot listen to %v: %w", addr, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := log.With("address", addr)

			l.Info("listening...")
			if err := svc.server.Serve(ln); err != nil {
				l.WithError(err).Fatal("cannot serve")
			}
		}()
	}

	wg.Wait()

	return nil
}

func (this *Service) prepare() (svc *service, err error) {
	fail := func(err error) (*service, error) {
		return nil, fmt.Errorf("cannot prepare service: %w", err)
	}

	forwardHandler := &ssh.ForwardedTCPHandler{}
	svc = &service{Service: this}

	svc.server.ConnCallback = svc.onNewConnConnection
	svc.server.Handler = svc.handler
	svc.server.LocalPortForwardingCallback = svc.onLocalPortForwardingRequested
	svc.server.ReversePortForwardingCallback = svc.onReversePortForwardingRequested
	svc.server.PublicKeyHandler = svc.handlePublicKey
	svc.server.PasswordHandler = svc.handlePassword
	svc.server.KeyboardInteractiveHandler = svc.handleKeyboardInteractiveChallenge
	svc.server.BannerHandler = svc.handleBanner
	svc.server.RequestHandlers = map[string]ssh.RequestHandler{
		"tcpip-forward":        forwardHandler.HandleSSHRequest,
		"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
	}
	if svc.server.HostSigners, err = this.loadHostSigners(); err != nil {
		return fail(err)
	}

	return svc, nil
}

func (this *Service) loadHostSigners() ([]ssh.Signer, error) {
	pk, err := crypto.EnsureFile(this.Configuration.Ssh.HostKey, &crypto.KeyRequirement{
		Type: crypto.KeyTypeEd25519,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot ensure host key: %w", err)
	}
	signer, err := gssh.NewSignerFromKey(pk)
	if err != nil {
		return nil, fmt.Errorf("cannot convert host key: %w", err)
	}
	return []ssh.Signer{signer}, nil
}

type service struct {
	*Service

	server ssh.Server
}

func (this *service) handler(sess ssh.Session) {
	l := log.With("remoteUser", sess.User()).
		With("remoteAddr", sess.RemoteAddr())

	l.With("remote", sess.RemoteAddr()).
		With("username", sess.User()).
		With("env", sess.Environ()).
		With("subsystem", sess.Subsystem()).
		With("command", sess.Command()).
		With("permissions", sess.Permissions()).
		Info("remote connected")

	u, err := user.Lookup(sess.User())
	if err != nil {
		l.WithError(err).Error("cannot lookup user")
		return
	}
	if u == nil {
		fmt.Fprintf(sess.Stderr(), "Too many failed login attempts")
		sess.Exit(6)
	}
	creds := u.ToCredentials()

	cmd := exec.Cmd{
		Path: u.Shell,
		Args: []string{"-" + filepath.Base(u.Shell)},
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &creds,
			Setsid:     true,
			//Setpgid:    true,
		},
	}
	cmd.Env = append(cmd.Env,
		"PATH="+os.Getenv("PATH"), // TODO! Improve
		"TZ="+os.Getenv("TZ"),     // TODO! Improve
	)
	cmd.Env = append(cmd.Env, sess.Environ()...)
	cmd.Env = append(cmd.Env,
		"HOME="+u.HomeDir,
		"USER="+u.Name,
		"LOGNAME="+u.Name,
		"SHELL="+u.Shell)

	if ssh.AgentRequested(sess) {
		l, err := ssh.NewAgentListener()
		if err != nil {
			log.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go ssh.ForwardAgentConnections(l, sess)
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
	}

	// TODO!  read $HOME/.ssh/environment.
	// TODO! Global configuration with environment

	// tODO! If not exist ~/.hushlogin display /etc/motd

	// TODO! Run Run $HOME/.ssh/rc, /etc/ssh/sshrc

	if ptyReq, winCh, isPty := sess.Pty(); isPty {
		cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
		f, err := pty.Start(&cmd)
		if err != nil {
			log.WithError(err).Info("cannot start process")
			return
		}
		go func() {
			for win := range winCh {
				this.setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, sess) // stdin
		}()
		io.Copy(sess, f) // stdout
	} else {
		cmd.Stdin = sess
		cmd.Stdout = sess
		cmd.Stderr = sess.Stderr()
	}
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			sess.Exit(ee.ExitCode())
		} else {
			log.WithError(err).With("command", cmd).Error("cannot execute command")
			sess.Exit(1)
		}
	}
}

func (this *service) onNewConnConnection(ctx ssh.Context, conn net.Conn) net.Conn {
	return conn
}

func (this *service) onLocalPortForwardingRequested(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	return true // TODO! Handle port forwarding
}

func (this *service) onReversePortForwardingRequested(ctx ssh.Context, bindHost string, bindPort uint32) bool {
	return true // TODO! Handle port forwarding
}

func (this *service) handlePublicKey(ctx ssh.Context, key ssh.PublicKey) bool {
	return false // TODO! Handle public keys
}

func (this *service) handlePassword(ctx ssh.Context, password string) bool {
	return false
}

func (this *service) handleKeyboardInteractiveChallenge(ctx ssh.Context, challenger gssh.KeyboardInteractiveChallenge) bool {
	// TODO! Here we can do the magic...
	answers, err := challenger("This is a very long text...\nNew lines\nAnd more...", "", nil, nil)
	if err != nil {
		log.WithError(err).Error("Mhh.. cannot handle keyboard interactive challenge")
		return false
	}
	log.With("answers", answers).Info("client answered")
	_, err = challenger("Something else...", "", nil, nil)
	if err != nil {
		log.WithError(err).Error("Mhh.. cannot handle keyboard interactive challenge")
		return false
	}
	return true
}

func (this *service) handleBanner(ctx ssh.Context) string {
	return "Hello world!\n" // TODO! Handle banner
}
