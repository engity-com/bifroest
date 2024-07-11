package main

import (
	"errors"
	"fmt"
	"github.com/creack/pty"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/interceptor"
	"github.com/engity/pam-oidc/pkg/user"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

func setWinsize(f *os.File, w, h int) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
	return err
}

func main() {

	native.DefaultProvider.SetLevel(level.Debug)
	interceptor.Default.Add(interceptor.NewFatal())

	authorizedKeys, err := ensureAuthorizedKeys(false, "var/authorized_keys")
	if err != nil {
		log.WithError(err).Fatal("cannot ensure authorized keys")
	}
	signer, err := ensurePrivateKey(nil, "var/ssh-key")
	if err != nil {
		log.WithError(err).Fatal("cannot ensure private key")
	}

	forwardHandler := &ssh.ForwardedTCPHandler{}

	srv := ssh.Server{
		Addr: ":2022",
		//MaxTimeout:  30 * time.Second,
		//IdleTimeout: 10 * time.Second,
		ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
			return conn
			//conn.(*net.TCPConn).Set
			cpid, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
			if errno != 0 {
				log.WithError(errno).Error("cannot fork process")
			}
			if cpid != 0 {
				log.With("pid", os.Getpid()).Info("hello from parent!")
				var wstatus syscall.WaitStatus
				if _, err := syscall.Wait4(int(cpid), &wstatus, 0, nil); err != nil {
					log.WithError(err).Error("cannot wait for forked child")
				}
				log.With("pid", os.Getpid()).Info("parent done")
				return nil
			}
			log.With("pid", os.Getpid()).Info("hello from child!")
			return conn
		},
		Handler: func(s ssh.Session) {
			l := log.With("remoteUser", s.User()).
				With("remoteAddr", s.RemoteAddr())

			l.With("remote", s.RemoteAddr()).
				With("username", s.User()).
				With("env", s.Environ()).
				With("subsystem", s.Subsystem()).
				With("command", s.Command()).
				With("permissions", s.Permissions()).
				Info("user connected")

			//if err := syscall.Setgid(1000); err != nil {
			//	log.WithError(err).Error("cannot set GID")
			//	return
			//}
			//if err := syscall.Setuid(1000); err != nil {
			//	log.WithError(err).Error("cannot set UID")
			//	return
			//}

			u, err := user.Lookup(s.User())
			if err != nil {
				l.WithError(err).Error("cannot lookup user")
				return
			}
			if u == nil {
				fmt.Fprintf(s.Stderr(), "Too many failed login attempts")
				s.Exit(6)
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
			cmd.Env = append(cmd.Env, s.Environ()...)
			cmd.Env = append(cmd.Env,
				"HOME="+u.HomeDir,
				"USER="+u.Name,
				"LOGNAME="+u.Name,
				"SHELL="+u.Shell)

			if ssh.AgentRequested(s) {
				l, err := ssh.NewAgentListener()
				if err != nil {
					log.Fatal(err)
				}
				defer func() { _ = l.Close() }()
				go ssh.ForwardAgentConnections(l, s)
				cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
			}

			// TODO!  read $HOME/.ssh/environment.
			// TODO! Global configuration with environment

			// tODO! If not exist ~/.hushlogin display /etc/motd

			// TODO! Run Run $HOME/.ssh/rc, /etc/ssh/sshrc

			if ptyReq, winCh, isPty := s.Pty(); isPty {
				cmd.Env = append(cmd.Env, "TERM="+ptyReq.Term)
				f, err := pty.Start(&cmd)
				if err != nil {
					log.WithError(err).Info("cannot start process")
					return
				}
				go func() {
					for win := range winCh {
						setWinsize(f, win.Width, win.Height)
					}
				}()
				go func() {
					io.Copy(f, s) // stdin
				}()
				io.Copy(s, f) // stdout
			} else {
				cmd.Stdin = s
				cmd.Stdout = s
				cmd.Stderr = s.Stderr()
			}
			if err := cmd.Wait(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					s.Exit(ee.ExitCode())
				} else {
					log.WithError(err).With("command", cmd).Error("cannot execute command")
					s.Exit(1)
				}
			}
		},
		LocalPortForwardingCallback: func(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
			return true
		},
		ReversePortForwardingCallback: func(ctx ssh.Context, bindHost string, bindPort uint32) bool {
			return true
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			_, ok := authorizedKeys[string(key.Marshal())]
			return ok
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			return ctx.User() == "testuser" && password == "tiger"
		},
		BannerHandler: func(ctx ssh.Context) string {
			return "Hello!\n"
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SftpHandler,
		},
		HostSigners: []ssh.Signer{signer},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
	}

	log.Fatal(srv.ListenAndServe())

}

func SftpHandler(sess ssh.Session) {
	server, err := sftp.NewServer(sess)
	if err != nil {
		log.WithError(err).Error("cannot create server")
		return
	}

	if err := server.Serve(); err == io.EOF {
		_ = server.Close()
		log.Info("sftp client exited session.")
	} else if err != nil {
		log.WithError(err).Error("sftp server completed with error")
	}
}
