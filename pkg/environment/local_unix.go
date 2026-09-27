//go:build unix

package environment

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

const (
	localProcessGroupGracePeriod  = 1500 * time.Millisecond
	localProcessGroupPollInterval = 25 * time.Millisecond
)

type processGroupOps struct {
	kill  func(int, syscall.Signal) error
	sleep func(time.Duration)
}

func defaultProcessGroupOps() processGroupOps {
	return processGroupOps{
		kill:  syscall.Kill,
		sleep: time.Sleep,
	}
}

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
	getEffectiveUserID         func() int
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
		getEffectiveUserID:         os.Geteuid,
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
	getEffectiveUserID := this.getEffectiveUserID
	if getEffectiveUserID == nil {
		getEffectiveUserID = os.Geteuid
	}
	creds, err := credentialsForUser(this.user, getEffectiveUserID())
	if err != nil {
		return nil, nil, nil, err
	}
	dir := this.user.HomeDir
	if !this.repository.conf.Directory.IsZero() {
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
			Credential: creds,
			Setpgid:    true,
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

func credentialsForUser(target *user.User, effectiveUserID int) (*syscall.Credential, error) {
	if target == nil {
		return nil, errors.System.Newf("cannot create local process credentials without a target user")
	}

	credentials := target.ToCredentials()
	if credentials.Uid != uint32(effectiveUserID) && effectiveUserID != 0 {
		return nil, errors.Permission.Newf(
			"cannot run local process as UID %d from effective UID %d: root privileges are required",
			credentials.Uid,
			effectiveUserID,
		)
	}
	return &credentials, nil
}

func (this *local) configureCmdForPty(cmd *exec.Cmd, pty, tty *os.File) error {
	cmd.SysProcAttr.Setpgid = false
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

func (this *local) startedProcessGroupID(cmd *exec.Cmd) int {
	return cmd.Process.Pid
}

func (this *local) signal(_ *exec.Cmd, processGroupID int, logger log.Logger, signal essh.Signal) {
	err := signalProcessFromSsh(signal, func(sig sys.Signal) error {
		return signalProcessGroup(processGroupID, sig.Native(), syscall.Kill)
	})
	if isProcessGroupGone(err) {
		// Ignored.
	} else if err != nil {
		logger.WithError(err).
			With("pgid", processGroupID).
			With("signal", signal).
			Warn("cannot send signal to process group")
	}
}

func (this *local) kill(_ *exec.Cmd, processGroupID int, logger log.Logger) {
	if err := cleanupProcessGroup(
		processGroupID,
		localProcessGroupGracePeriod,
		localProcessGroupPollInterval,
		defaultProcessGroupOps(),
	); err != nil {
		logger.WithError(err).
			With("pgid", processGroupID).
			Warn("cannot completely terminate process group")
	}
}

func signalProcessGroup(processGroupID int, signal syscall.Signal, kill func(int, syscall.Signal) error) error {
	target, exists, err := probeProcessGroup(processGroupID, kill)
	if err != nil || !exists {
		return err
	}
	if err := kill(target, signal); isProcessGroupGone(err) {
		return nil
	} else if err != nil {
		return errors.System.Newf("cannot send %s to process group %d: %w", signal, processGroupID, err)
	}
	return nil
}

func cleanupProcessGroup(processGroupID int, gracePeriod, pollInterval time.Duration, ops processGroupOps) error {
	if gracePeriod < 0 {
		gracePeriod = 0
	}
	if pollInterval <= 0 {
		pollInterval = gracePeriod
		if pollInterval <= 0 {
			pollInterval = time.Nanosecond
		}
	}

	target, exists, err := probeProcessGroup(processGroupID, ops.kill)
	if err != nil || !exists {
		return err
	}

	var result error
	if err := ops.kill(target, syscall.SIGTERM); isProcessGroupGone(err) {
		return nil
	} else if err != nil {
		result = errors.System.Newf("cannot send SIGTERM to process group %d: %w", processGroupID, err)
	}

	remaining := gracePeriod
	for {
		if remaining > 0 {
			delay := min(remaining, pollInterval)
			ops.sleep(delay)
			remaining -= delay
		}

		target, exists, err = probeProcessGroup(processGroupID, ops.kill)
		if err != nil {
			return goerrors.Join(result, err)
		}
		if !exists {
			return result
		}
		if remaining <= 0 {
			break
		}
	}

	if err := ops.kill(target, syscall.SIGKILL); isProcessGroupGone(err) {
		return result
	} else if err != nil {
		return goerrors.Join(result, errors.System.Newf("cannot send SIGKILL to process group %d: %w", processGroupID, err))
	}
	return result
}

func probeProcessGroup(processGroupID int, kill func(int, syscall.Signal) error) (target int, exists bool, err error) {
	if processGroupID <= 0 {
		return 0, false, errors.System.Newf("invalid process group ID: %d", processGroupID)
	}
	target = -processGroupID
	if err := kill(target, 0); isProcessGroupGone(err) {
		return target, false, nil
	} else if err != nil {
		return target, false, errors.System.Newf("cannot probe process group %d: %w", processGroupID, err)
	}
	return target, true, nil
}

func isProcessGroupGone(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone)
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
