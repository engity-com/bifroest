package environment

import (
	"context"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"golang.org/x/net/proxy"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type docker struct {
	repository *DockerRepository
	session    session.Session
	token      *dockerToken
	apiClient  client.APIClient
}

func (this *docker) Session() session.Session {
	return this.session
}

func (this *docker) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.repository.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *docker) Run(t Task) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(msg string, args ...any) (int, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	apiClient := this.apiClient
	defer common.IgnoreCloseError(apiClient)

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run docker environment")
	}
	sshSess := t.SshSession()
	l := t.Logger()

	opts := container.ExecOptions{
		User:         this.token.user,
		WorkingDir:   this.token.directory,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
	}

	ev := sys.EnvVars{}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(t.SshSession().Environ()...)
	ev.Set("BIFROEST_SESSION_ID", sess.Id().String())

	switch t.TaskType() {
	case TaskTypeShell:
		if v := sshSess.Command(); len(v) > 0 {
			opts.Cmd = append(this.token.execCommand, v...)
		} else {
			opts.Cmd = slices.Clone(this.token.shellCommand)
		}
	case TaskTypeSftp:
		opts.Cmd = slices.Clone(this.token.sftpCommand)
	default:
		return failf("illegal task type: %v", t.TaskType())
	}

	// TODO! Does not work because we need to forward a correct socket into the container
	// in this case we have to mount a directory into the container to ensure this.
	// --------
	// if ssh.AgentRequested(sshSess) {
	// 	al, err := ssh.NewAgentListener()
	// 	if err != nil {
	// 		return failf("cannot listen to agent: %w", err)
	// 	}
	// 	defer common.IgnoreCloseError(al)
	// go ssh.ForwardAgentConnections(al, sshSess)
	// 	ev.Set("SSH_AUTH_SOCK", al.Addr().String())
	// }

	var execId string
	if ptyReq, winCh, isPty := sshSess.Pty(); isPty {
		ev.Set("TERM", ptyReq.Term)
		go func() {
			for {
				win, ok := <-winCh
				if !ok {
					return
				}
				if execId != "" {
					if err := apiClient.ContainerExecResize(sshSess.Context(), execId, container.ResizeOptions{
						Height: uint(win.Height),
						Width:  uint(win.Width),
					}); err != nil {
						l.WithError(err).Warn("cannot set window size; ignoring")
					}
				}
			}
		}()
		opts.Tty = true
		opts.ConsoleSize = &[2]uint{80, 40}
	}
	opts.Env = ev.Strings()

	if e, err := apiClient.ContainerExecCreate(t.Context(), this.token.containerId, opts); err != nil {
		return failf("cannot execute command: %w", err)
	} else {
		execId = e.ID
	}

	ea, err := apiClient.ContainerExecAttach(t.Context(), execId, container.ExecAttachOptions{
		Tty:         opts.Tty,
		ConsoleSize: opts.ConsoleSize,
	})
	if err != nil {
		return failf("cannot attach to execution #%v: %w", execId, err)
	}

	copyDone := make(chan error, 2)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			defer close(copyDone)
		}()
	}()

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		var cErr error
		if opts.Tty {
			_, cErr = io.Copy(sshSess, ea.Reader)
		} else {
			_, cErr = stdcopy.StdCopy(sshSess, sshSess.Stderr(), ea.Reader)
		}
		if this.isRelevantError(cErr) {
			copyDone <- cErr
		} else {
			copyDone <- nil
		}
		l.Trace("finished copy output")
	}()
	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		if _, err := io.Copy(ea.Conn, sshSess); this.isRelevantError(err) {
			copyDone <- err
		} else {
			copyDone <- nil
		}
		l.Trace("finished copy input")
	}()

	finish := func() (int, error) {
		ei, iErr := apiClient.ContainerExecInspect(sshSess.Context(), execId)
		if iErr != nil {
			return failf("cannot inspect execution #%s: %w", execId, iErr)
		}
		if ei.Running {
			return -1, nil
		}
		return ei.ExitCode, nil
	}

	for {
		select {
		// TODO! Send kill to child command
		case <-t.Context().Done():
			if err := t.Context().Err(); err != nil && rErr == nil {
				rErr = err
			}
			return -2, rErr
		case err, ok := <-copyDone:
			ea.Close()
			_ = ea.CloseWrite()
			if ok && err != nil && rErr == nil {
				return -1, err
			}
			if rErr == nil {
				if ec, err := finish(); err != nil {
					return -1, err
				} else if ec >= 0 {
					return ec, nil
				}
			}
		}
	}
}

func (this *docker) Dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	ok, err := this.repository.removeContainer(ctx, this.apiClient, this.token.containerId)
	if err != nil {
		return fail(err)
	}

	return ok, nil
}

func (this *docker) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}

func (this *docker) IsPortForwardingAllowed(_ string, _ uint32) (bool, error) {
	return this.token.portForwardingAllowed, nil
}

func (this *docker) NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error) {
	if !this.token.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	// TODO! Should be configured better....
	socks5, err := proxy.SOCKS5("tcp", ":8800", &proxy.Auth{}, proxy.Direct)
	if err != nil {
		return nil, err
	}
	socks5C := socks5.(proxy.ContextDialer)

	dest := net.JoinHostPort(host, strconv.FormatInt(int64(port), 10))
	return socks5C.DialContext(ctx, "tcp", dest)
}
