package environment

import (
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

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

	apiClient := this.repository.apiClient
	defer common.IgnoreCloseError(apiClient)

	auth := t.Authorization()
	sess := auth.FindSession()
	if sess == nil {
		return failf("authorization without session is not supported to run docker environment")
	}
	sshSess := t.SshSession()
	l := t.Logger()

	opts := container.ExecOptions{
		User:         this.user,
		WorkingDir:   this.directory,
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
			opts.Cmd = append(this.execCommand, v...)
		} else {
			opts.Cmd = slices.Clone(this.shellCommand)
		}
	case TaskTypeSftp:
		opts.Cmd = slices.Clone(this.sftpCommand)
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

	if e, err := apiClient.ContainerExecCreate(t.Context(), this.containerId, opts); err != nil {
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

func (this *docker) IsPortForwardingAllowed(_ string, _ uint32) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (this *docker) NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error) {
	if !this.portForwardingAllowed {
		return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
	}

	connId, err := connection.NewId()
	if err != nil {
		return nil, err
	}

	return this.impSession.InitiateDirectTcp(ctx, connId, host, port)
}
