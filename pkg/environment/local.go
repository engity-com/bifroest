package environment

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
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

	Ensurer user.Ensurer
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

	result := Local{
		flow: flow,
		conf: conf,

		Ensurer: user.ExecutionBasedEnsurer{
			Executor: &sys.StandardExecutor{
				UsingSudo: true,
			},
			AllowBadNames:      true,
			SkipIllegalEntries: true,
		},
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

	req, createIfAbsent, updateIfDifferent, err := this.renderContext(t)
	if err != nil {
		return fail(err)
	}

	u, err := this.ensureUser(req, createIfAbsent, updateIfDifferent)
	if err != nil {
		return fail(err)
	}

	if u == nil {
		t.Logger().Info("no user could be resolved; exit now")
		return nil
	}

	if err := this.runCommand(t, u); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Local) renderContext(t Task) (req *user.Requirement, createIfAbsent, updateIfDifferent bool, err error) {
	fail := func(err error) (*user.Requirement, bool, bool, error) {
		return nil, false, false, err
	}

	if req, err = this.conf.User.Render(nil, t); err != nil {
		return fail(fmt.Errorf("cannot render user requirement: %w", err))
	}

	if createIfAbsent, err = this.conf.CreateIfAbsent.Render(t); err != nil {
		return fail(fmt.Errorf("cannot render createIfAbsent: %w", err))
	}

	if updateIfDifferent, err = this.conf.UpdateIfDifferent.Render(t); err != nil {
		return fail(fmt.Errorf("cannot render updateIfDifferent: %w", err))
	}

	return req, createIfAbsent, updateIfDifferent, nil
}

func (this *Local) ensureUser(req *user.Requirement, createIfAbsent, updateIfDifferent bool) (u *user.User, err error) {
	u, err = this.Ensurer.Ensure(req, &user.EnsureOpts{
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
	sess := t.Session()

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
		if rc := t.Session().RawCommand(); len(rc) > 0 {
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
			log.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		go ssh.ForwardAgentConnections(l, sess)
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK"+l.Addr().String())
	}

	// TODO!  read $HOME/.ssh/environment.
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
		defer func() { _ = f.Close() }()

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
		return t.Session().Exit(ec)
	}

	return nil
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
