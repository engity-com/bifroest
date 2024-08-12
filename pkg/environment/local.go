package environment

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
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

func (this *Local) Run(t Task) error {
	fail := func(err error) error {
		return err
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

	if err := this.runCommand(t, u); err != nil {
		return fail(err)
	}

	return nil
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

func (this *Local) runCommand(t Task, u *user.User) error {
	l := t.Logger()
	creds := u.ToCredentials()
	sess := t.SshSession()

	cmd := exec.Cmd{
		Dir: u.HomeDir,
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &creds,
			Setsid:     true,
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
			return fmt.Errorf("cannot resolve the location of the server's executable location: %w", err)
		}
		cmd.Path = efn
		cmd.Args = []string{efn, "sftp-server"}
	default:
		return fmt.Errorf("illegal task type: %v", t.TaskType())
	}

	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	ev.AddAllOf(t.Authorization().EnvVars())
	ev.Add(sess.Environ()...)
	ev.Set(
		"HOME", u.HomeDir,
		"USER", u.Name,
		"LOGNAME", u.Name,
		"SHELL", u.Shell,
	)

	if ssh.AgentRequested(sess) {
		l, err := ssh.NewAgentListener()
		if err != nil {
			return fmt.Errorf("cannot listen to agent: %w", err)
		}
		defer common.IgnoreCloseError(l)
		go ssh.ForwardAgentConnections(l, sess)
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
	}

	// TODO! Global configuration with environment
	// tODO! If not exist ~/.hushlogin display /etc/motd

	if ptyReq, winCh, isPty := sess.Pty(); isPty {
		ev.Set("TERM", ptyReq.Term)
		cmd.Env = ev.Strings()
		f, err := pty.Start(&cmd)
		if err != nil {
			return fmt.Errorf("cannot start process %v: %w", cmd.Args, err)
		}
		defer this.killIfNeeded(t, &cmd)
		defer common.IgnoreCloseError(f)

		go func() {
			for win := range winCh {
				if err := this.setWinsize(f, win.Width, win.Height); err != nil {
					l.WithError(err).Warn("cannot set winsize; ignoring")
				}
			}
		}()
		go func() {
			_, _ = io.Copy(f, sess) // stdin
		}()
		_, _ = io.Copy(sess, f) // stdout
	} else {
		cmd.Env = ev.Strings()
		cmd.Stdin = sess
		cmd.Stdout = sess
		if t.TaskType() == TaskTypeSftp {
			cmd.Stderr = &log.LoggingWriter{
				Logger:         l,
				LevelExtractor: level.FixedLevelExtractor(level.Error),
			}
		} else {
			cmd.Stderr = sess.Stderr()
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("cannot start process %v: %w", cmd.Args, err)
		}
		defer this.killIfNeeded(t, &cmd)
	}

	if state, err := cmd.Process.Wait(); err != nil {
		return err
	} else if ec := state.ExitCode(); ec != 0 {
		return t.SshSession().Exit(ec)
	}

	return nil
}

func (this *Local) Close() error {
	return this.userRepository.Close()
}

func (this *Local) killIfNeeded(t Task, cmd *exec.Cmd) {
	go func() {
		ctx := t.Context()
		select {
		case <-ctx.Done():
			// Just to be sure, kill the process to do not leave anything behind...
			_ = cmd.Process.Kill()
		}
	}()
}
