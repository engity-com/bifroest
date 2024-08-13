package environment

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
	"github.com/gliderlabs/ssh"
	"github.com/kardianos/osext"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

type Local struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentLocal

	userRepository user.CloseableRepository
}

func NewLocal(flow configuration.FlowName, conf *configuration.EnvironmentLocal) (*Local, error) {
	fail := func(err error) (*Local, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*Local, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	userRepository, err := user.DefaultRepositoryProvider.Create()
	if err != nil {
		return nil, err
	}

	result := Local{
		flow:           flow,
		conf:           conf,
		userRepository: userRepository,
	}

	return &result, nil
}

func (this *Local) WillBeAccepted(req Request) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(req); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *Local) Banner(req Request) (io.ReadCloser, error) {
	b, err := this.conf.Banner.Render(req)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(strings.NewReader(b)), nil
}

func (this *Local) Run(t Task) (int, error) {
	fail := func(err error) (int, error) {
		return -1, err
	}

	var u *user.User
	var err error
	if this.conf.User.IsDefaultButNameAndUid() {
		if name := this.conf.User.Name; !name.IsZero() {
			if u, err = this.lookupByName(t, name); err != nil {
				return fail(err)
			}
		} else if uid := this.conf.User.Uid; uid != nil {
			if u, err = this.lookupByUid(t, *uid); err != nil {
				return fail(err)
			}
		}
	}

	if u == nil {
		if u, err = this.ensureUserByTask(t); err != nil {
			return fail(err)
		}
	}

	return this.runCommand(t, u)
}

func (this *Local) ensureUserByTask(t Task) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	req, err := this.conf.User.Render(nil, t)
	if err != nil {
		return failf("cannot render user requirement: %w", err)
	}

	createIfAbsent, err := this.conf.CreateIfAbsent.Render(t)
	if err != nil {
		return failf("cannot render createIfAbsent: %w", err)
	}

	updateIfDifferent, err := this.conf.UpdateIfDifferent.Render(t)
	if err != nil {
		return failf("cannot render updateIfDifferent: %w", err)
	}

	return this.ensureUser(req, createIfAbsent, updateIfDifferent)
}

func (this *Local) lookupByUid(t Task, tmpl template.TextMarshaller[user.Id, *user.Id]) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	uid, err := tmpl.Render(t)
	if err != nil {
		return failf("cannot render UID: %w", err)
	}

	return this.userRepository.LookupById(uid)
}

func (this *Local) lookupByName(t Task, tmpl template.String) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	name, err := tmpl.Render(t)
	if err != nil {
		return failf("cannot render user name: %w", err)
	}

	return this.userRepository.LookupByName(name)
}

func (this *Local) ensureUser(req *user.Requirement, createIfAbsent, updateIfDifferent bool) (u *user.User, err error) {
	u, _, err = this.userRepository.Ensure(req, &user.EnsureOpts{
		CreateAllowed: &createIfAbsent,
		ModifyAllowed: &updateIfDifferent,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot ensure user: %w", err)
	}
	return u, nil
}

func (this *Local) runCommand(t Task, u *user.User) (exitCode int, rErr error) {
	l := t.Logger()
	creds := u.ToCredentials()
	sshSess := t.SshSession()

	cmd := exec.Cmd{
		Dir: u.HomeDir,
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &creds,
		},
	}

	ev := sys.EnvVars{
		"PATH": this.getPathEnv(),
	}

	switch t.TaskType() {
	case TaskTypeShell:
		cmd.Path = u.Shell
		if rc := t.SshSession().RawCommand(); len(rc) > 0 {
			cmd.Args = []string{filepath.Base(u.Shell), "-c", rc}
		} else {
			cmd.Args = []string{"-" + filepath.Base(u.Shell)}
		}
	case TaskTypeSftp:
		efn, err := osext.Executable()
		if err != nil {
			return -1, fmt.Errorf("cannot resolve the location of the server's executable location: %w", err)
		}
		cmd.Path = efn
		cmd.Args = []string{efn, "sftp-server"}
	default:
		return -1, fmt.Errorf("illegal task type: %v", t.TaskType())
	}

	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(sshSess.Environ()...)
	ev.Set(
		"HOME", u.HomeDir,
		"USER", u.Name,
		"LOGNAME", u.Name,
		"SHELL", u.Shell,
	)

	if ssh.AgentRequested(sshSess) {
		l, err := ssh.NewAgentListener()
		if err != nil {
			return -1, fmt.Errorf("cannot listen to agent: %w", err)
		}
		defer common.IgnoreCloseError(l)
		go ssh.ForwardAgentConnections(l, sshSess)
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
	}

	// TODO! Global configuration with environment
	// tODO! If not exist ~/.hushlogin display /etc/motd

	cmd.Stdin = sshSess
	cmd.Stdout = sshSess
	if t.TaskType() == TaskTypeSftp {
		cmd.Stderr = &log.LoggingWriter{
			Logger:         l,
			LevelExtractor: level.FixedLevelExtractor(level.Error),
		}
	} else {
		cmd.Stderr = sshSess.Stderr()
	}

	var fPty, fTty *os.File
	if ptyReq, winCh, isPty := sshSess.Pty(); isPty {
		ev.Set("TERM", ptyReq.Term)
		var err error
		fPty, fTty, err = pty.Open()
		if err != nil {
			return -1, fmt.Errorf("cannot allocate pty: %w", err)
		}
		defer common.IgnoreCloseError(fPty)
		defer common.IgnoreCloseError(fTty)
		cmd.SysProcAttr.Setsid = true
		cmd.SysProcAttr.Setctty = true
		cmd.Stderr = fTty
		cmd.Stdout = fTty
		cmd.Stdin = fTty

		go func() {
			for {
				win, ok := <-winCh
				if !ok {
					return
				}
				size := pty.Winsize{uint16(win.Height), uint16(win.Width), 0, 0}
				if err := pty.Setsize(fPty, &size); err != nil {
					l.WithError(err).Warn("cannot set winsize; ignoring")
				}
			}
		}()
	}
	cmd.Env = ev.Strings()

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("cannot start process %v: %w", cmd.Args, err)
	}
	l.With("pid", cmd.Process.Pid).
		Debug("user's process started")

	type doneT struct {
		exitCode int
		err      error
	}
	processDone := make(chan doneT, 1)
	copyDone := make(chan error, 2)
	var activeRoutines sync.WaitGroup
	defer func() {
		go func() {
			activeRoutines.Wait()
			defer close(copyDone)
			defer close(processDone)
		}()
	}()

	if fPty != nil {
		doCopy := func(from io.Reader, to io.Writer, name string) {
			defer activeRoutines.Done()
			if _, err := io.Copy(to, from); this.isRelevantError(err) {
				copyDone <- err
			} else {
				copyDone <- nil
			}
			l.Tracef("finished copy %s", name)
		}
		activeRoutines.Add(1)
		go doCopy(fPty, sshSess, "pty -> ssh")
		activeRoutines.Add(1)
		go doCopy(sshSess, fPty, "ssh -> pty")
	}

	activeRoutines.Add(1)
	go func() {
		defer activeRoutines.Done()
		if state, err := cmd.Process.Wait(); err != nil {
			processDone <- doneT{-1, err}
		} else {
			processDone <- doneT{state.ExitCode(), nil}
		}
		l.Trace("finished process")
	}()

	defer this.kill(&cmd, l)

	for {
		select {
		case <-t.Context().Done():
			if err := t.Context().Err(); err != nil && rErr == nil {
				rErr = err
			}
			return -2, rErr
		case status := <-processDone:
			if status.err != nil && rErr == nil {
				rErr = status.err
			}
			return status.exitCode, rErr
		case err := <-copyDone:
			if err != nil && rErr == nil {
				rErr = err
				return -1, rErr
			}
		}
	}
}

func (this *Local) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}

func (this *Local) Close() error {
	return this.userRepository.Close()
}

func (this *Local) kill(cmd *exec.Cmd, logger log.Logger) {
	// TODO! We should consider the whole tree...
	if err := cmd.Process.Kill(); errors.Is(err, os.ErrProcessDone) {
		// Ok, great.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			Warn("cannot kill process")
	}
}
