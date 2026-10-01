//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *local) newAgentNamedPipe() (net.NamedPipe, error) {
	return net.NewNamedPipeForUser(
		"ssh-agent",
		strconv.FormatUint(uint64(this.user.Uid), 10),
		strconv.FormatUint(uint64(this.user.Group.Gid), 10),
	)
}

type local struct {
	repository                 *LocalRepository
	session                    session.Session
	user                       *user.User
	portForwardingAllowed      bool
	deleteUserOnDispose        bool
	deleteHomeTogetherWithUser bool
	killProcessesOnDispose     bool
	expectedHomeDir            string
	allowSystemUsers           bool
	deferred                   bool
	token                      *localToken
	accountMissing             bool
}

func (this *local) reverseTCPUnprivilegedUser() bool {
	return this.user != nil && this.user.Uid != 0
}

func (this *LocalRepository) new(u *user.User, sess session.Session, portForwardingAllowed bool, lt *localToken) *local {
	return &local{
		repository:                 this,
		session:                    sess,
		user:                       u,
		portForwardingAllowed:      portForwardingAllowed,
		deleteUserOnDispose:        lt.User.DeleteOnDispose,
		deleteHomeTogetherWithUser: lt.User.DeleteHomeTogetherWithUser,
		killProcessesOnDispose:     lt.User.KillProcessesOnDispose,
		expectedHomeDir:            lt.User.HomeDir,
		allowSystemUsers:           lt.User.AllowSystemUsers,
		token:                      lt,
	}
}

func (this *local) configureShellCmd(t Task, cmd *exec.Cmd) error {
	raw := t.SshSession().RawCommand()
	source := &this.repository.conf.ShellCommand
	property := "shellCommand"
	if raw != "" {
		source = &this.repository.conf.ExecCommandPrefix
		property = "execCommandPrefix"
	}
	if source.IsZero() {
		cmd.Path = this.user.Shell
		if raw != "" {
			cmd.Args = []string{filepath.Base(this.user.Shell), "-c", raw}
		} else {
			cmd.Args = []string{"-" + filepath.Base(this.user.Shell)}
		}
		return nil
	}
	args, err := source.Render(t)
	if err != nil {
		return errors.Config.Newf("cannot evaluate %s: %w", property, err)
	}
	if len(args) == 0 || args[0] == "" {
		return errors.Config.Newf("%s requires an executable", property)
	}
	cmd.Path, err = exec.LookPath(args[0])
	if err != nil {
		return errors.Config.Newf("cannot find %s executable %q: %w", property, args[0], err)
	}
	if raw != "" {
		cmd.Args = append(args, raw)
	} else {
		cmd.Args = args
	}
	return nil
}

func (this *local) createCmdAndEnv(t Task) (*exec.Cmd, *sys.EnvVars, func(), error) {
	creds := this.user.ToCredentials()
	dir := this.user.HomeDir
	if !this.repository.conf.Directory.IsZero() {
		var err error
		dir, err = this.repository.conf.Directory.Render(t)
		if err != nil {
			return nil, nil, nil, errors.Config.Newf("cannot evaluate directory: %w", err)
		}
		fi, err := os.Stat(dir)
		if err != nil {
			return nil, nil, nil, errors.Config.Newf("cannot access directory %q: %w", dir, err)
		}
		if !fi.IsDir() {
			return nil, nil, nil, errors.Config.Newf("directory %q is not a directory", dir)
		}
	}
	cmd := exec.Cmd{
		Dir: dir,
		SysProcAttr: &syscall.SysProcAttr{
			Credential: &creds,
		},
	}

	ev := sys.EnvVars{
		"PATH": this.getPathEnv(),
	}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.Set("TZ", v)
	}
	if err := applyTaskEnvironment(&ev, localTargetOs, t); err != nil {
		return nil, nil, nil, err
	}
	ev.Set(
		"HOME", this.user.HomeDir,
		"USER", this.user.Name,
		"LOGNAME", this.user.Name,
		"SHELL", this.user.Shell,
	)

	return &cmd, &ev, func() {}, nil
}

func (this *local) runConPTY(Task, *exec.Cmd) (int, error) {
	return -1, errors.System.Newf("ConPTY is only available on Windows")
}

func (this *local) configureCmdForPty(cmd *exec.Cmd, pty, tty *os.File) error {
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true

	if err := syscall.SetNonblock(int(pty.Fd()), true); err != nil {
		return err
	}
	if err := syscall.SetNonblock(int(tty.Fd()), true); err != nil {
		return err
	}
	return nil
}

func (this *local) getPathEnv() string {
	if v := os.Getenv("PATH"); v != "" {
		return v
	}
	return "/bin:/usr/bin"
}

func (this *local) signal(cmd *exec.Cmd, logger log.Logger, signal essh.Signal) {
	err := signalProcessFromSsh(signal, func(sig sys.Signal) error {
		return sig.SendToProcess(cmd.Process)
	})
	if errors.Is(err, os.ErrProcessDone) {
		// Ignored.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			With("signal", signal).
			Warn("cannot send signal to process")
	}
}

func (this *local) dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	this.deferred = false
	if this.repository.coordinator != nil && this.session != nil && localSessionHasActiveConnections(this.session) {
		this.deferred = true
		return false, nil
	}
	if !this.deleteUserOnDispose && !this.killProcessesOnDispose {
		return false, nil
	}
	if this.session == nil {
		return fail(errors.System.Newf("cannot clean up local account without a session"))
	}
	if this.repository.coordinator == nil && (this.deleteUserOnDispose ||
		(this.killProcessesOnDispose && !this.token.User.ProcessesKilledOnDispose)) {
		return fail(errors.System.Newf("cannot clean up local account without a session coordinator"))
	}
	if this.repository.coordinator != nil {
		this.repository.coordinator.mu.Lock()
		defer this.repository.coordinator.mu.Unlock()
	}
	if this.repository.coordinator != nil && localSessionHasActiveConnections(this.session) {
		this.deferred = true
		return false, nil
	}
	stored, err := this.session.EnvironmentToken(ctx)
	if err != nil {
		return fail(err)
	}
	var lt localToken
	if err := json.Unmarshal(stored, &lt); err != nil || lt.Version != 2 || lt.User.Name != this.user.Name ||
		lt.User.Uid == nil || *lt.User.Uid != this.user.Uid || lt.User.DeleteOnDispose != this.deleteUserOnDispose ||
		lt.User.KillProcessesOnDispose != this.killProcessesOnDispose || lt.User.AllowSystemUsers != this.allowSystemUsers {
		return fail(errors.System.Newf("cannot verify local account token before cleanup: %v", err))
	}
	if lt.User.ProcessesKilledOnDispose {
		this.token.User.ProcessesKilledOnDispose = true
	}
	if !this.accountMissing {
		current, err := this.repository.userRepository.LookupById(ctx, this.user.Uid)
		if errors.Is(err, user.ErrNoSuchUser) {
			this.accountMissing = true
		} else if err != nil {
			return fail(err)
		} else if current.Name != this.user.Name {
			this.accountMissing = true
		} else if current.Uid == 0 && !this.allowSystemUsers {
			return fail(errors.System.Newf("local account UID 0 is protected"))
		}
	}
	if this.accountMissing && this.user.Uid == 0 && !this.allowSystemUsers {
		return fail(errors.System.Newf("local account UID 0 is protected"))
	}
	disposed := false
	if this.killProcessesOnDispose && !this.token.User.ProcessesKilledOnDispose {
		ready, err := this.repository.coordinator.canKillProcesses(ctx, this.session, this.user.Name, this.user.Uid.String())
		if err != nil {
			return fail(err)
		}
		if !ready {
			this.deferred = true
			return false, nil
		}
		if this.accountMissing {
			logger := this.repository.logger().With("session", this.session).With("name", this.user.Name).With("uid", this.user.Uid)
			if this.deleteUserOnDispose {
				logger.Warn("skipping process and account cleanup: original local account identity is no longer verifiable; inspect remaining processes and files manually")
			} else {
				logger.Warn("skipping process cleanup: original local account identity is no longer verifiable; inspect remaining processes manually")
			}
			return true, nil // local.Dispose clears the token after all active sessions have ended.
		}
		killer, ok := this.repository.userRepository.(interface {
			KillProcessesByIdentity(context.Context, user.Id, string) error
		})
		if !ok {
			return fail(errors.System.Newf("local user repository does not support verified process cleanup"))
		}
		if err := killer.KillProcessesByIdentity(ctx, this.user.Uid, this.user.Name); err != nil {
			return fail(err)
		}
		lt.User.ProcessesKilledOnDispose = true
		encoded, err := json.Marshal(&lt)
		if err != nil {
			return fail(err)
		}
		if err := updateLocalCleanupToken(ctx, this.session, stored, encoded); err != nil {
			return fail(err)
		}
		this.token.User.ProcessesKilledOnDispose = true
		disposed = true
	}
	if this.repository.coordinator != nil && localSessionHasActiveConnections(this.session) {
		this.deferred = true
		return disposed, nil
	}
	if this.deleteUserOnDispose {
		if this.accountMissing {
			ready, err := this.repository.coordinator.canKillProcesses(ctx, this.session, this.user.Name, this.user.Uid.String())
			if err != nil {
				return fail(err)
			}
			if !ready {
				this.deferred = true
				return disposed, nil
			}
			if this.deleteHomeTogetherWithUser {
				cleaner, ok := this.repository.userRepository.(interface {
					DeleteHomeByAbsentIdentity(context.Context, user.Id, string, string) error
				})
				if !ok {
					return fail(errors.System.Newf("local user repository does not support verified cleanup of an absent account home"))
				}
				if err := cleaner.DeleteHomeByAbsentIdentity(ctx, this.user.Uid, this.user.Name, this.expectedHomeDir); err != nil {
					return fail(err)
				}
				disposed = true
			}
			this.repository.logger().With("session", this.session).With("name", this.user.Name).
				With("uid", this.user.Uid).Warn("skipping account deletion: original local account identity is no longer verifiable; inspect remaining files manually")
			return true, nil
		}
		active, err := this.repository.coordinator.otherActive(ctx, this.session, this.user.Name, this.user.Uid.String())
		if err != nil {
			return fail(err)
		}
		if active {
			this.deferred = true
			return disposed, nil
		}
		deleter, ok := this.repository.userRepository.(interface {
			DeleteByIdentity(context.Context, user.Id, string, string, *user.DeleteOpts) error
		})
		if !ok {
			return fail(errors.System.Newf("local user repository does not support verified account deletion"))
		}
		if err := deleter.DeleteByIdentity(ctx, this.user.Uid, this.user.Name, this.expectedHomeDir, &user.DeleteOpts{
			HomeDir:       common.P(this.deleteHomeTogetherWithUser),
			KillProcesses: common.P(false),
		}); errors.Is(err, user.ErrNoSuchUser) {
			// Ok, continue....
		} else if err != nil {
			return fail(err)
		} else {
			disposed = true
			if err := this.session.SetEnvironmentToken(ctx, nil); err != nil {
				return fail(err)
			}
		}
	}

	return disposed, nil
}
