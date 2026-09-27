//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

const localTargetOs = sys.OsWindows

func (this *local) newAgentNamedPipe() (net.NamedPipe, error) {
	return net.NewNamedPipeForSid("ssh-agent", this.user.SID)
}

type local struct {
	repository             *LocalRepository
	session                session.Session
	user                   windowsLocalAccount
	token                  *localToken
	portForwardingAllowed  bool
	deleteOnDispose        bool
	deleteProfileOnDispose bool
	killProcessesOnDispose bool
	allowSystemUsers       bool
	deferred               bool
	accountMissing         bool
}

func (this *local) reverseTCPUnprivilegedUser() bool { return false }

func (this *LocalRepository) new(user windowsLocalAccount, sess session.Session, portForwardingAllowed bool, lt *localToken) *local {
	return &local{
		repository:             this,
		session:                sess,
		user:                   user,
		token:                  lt,
		portForwardingAllowed:  portForwardingAllowed,
		deleteOnDispose:        lt.Version == 2 && localWindowsCleanupAllowed(user, lt.AllowSystemUsers, lt.DeleteOnDispose),
		deleteProfileOnDispose: lt.Version == 2 && localWindowsCleanupAllowed(user, lt.AllowSystemUsers, lt.DeleteOnDispose && lt.DeleteProfileOnDispose),
		killProcessesOnDispose: lt.Version == 2 && localWindowsCleanupAllowed(user, lt.AllowSystemUsers, lt.KillProcessesOnDispose),
		allowSystemUsers:       lt.AllowSystemUsers,
	}
}

func (this *local) createCmdAndEnv(t Task) (*exec.Cmd, *sys.EnvVars, func(), error) {
	token, release, err := this.user.logon()
	if err != nil {
		return nil, nil, nil, errors.System.Newf("cannot log on as local account %q: %w", this.user.Name, err)
	}
	fail := func(err error) (*exec.Cmd, *sys.EnvVars, func(), error) {
		release()
		return nil, nil, nil, err
	}
	home, err := token.GetUserProfileDirectory()
	if err != nil {
		return fail(errors.System.Newf("cannot resolve local account's profile directory: %w", err))
	}
	dir := home
	if !this.repository.conf.Directory.IsZero() {
		dir, err = this.repository.conf.Directory.Render(t)
		if err != nil {
			return fail(errors.Config.Newf("cannot evaluate environment's directory: %w", err))
		}
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fail(errors.Config.Newf("cannot evaluate environment's directory (%q): %w", dir, err))
	}
	if !fi.IsDir() {
		return fail(errors.Config.Newf("environment's directory (%q) isn't a directory", dir))
	}

	cmd := exec.Cmd{
		Dir:         dir,
		SysProcAttr: &syscall.SysProcAttr{Token: syscall.Token(token)},
	}

	base, err := token.Environ(false)
	if err != nil {
		return fail(errors.System.Newf("cannot get local account's environment: %w", err))
	}
	ev := sys.EnvVars{}
	for _, entry := range base {
		if !strings.HasPrefix(entry, "=") {
			addEnvironmentEntries(&ev, localTargetOs, []string{entry})
		}
	}
	if !hasWindowsPath(ev) {
		ev.SetCanonical("PATH", this.getPathEnv())
	}
	if v, ok := os.LookupEnv("TZ"); ok {
		ev.SetCanonical("TZ", v)
	}
	if err := applyTaskEnvironment(&ev, localTargetOs, t); err != nil {
		return fail(err)
	}
	host, err := os.Hostname()
	if err != nil {
		return fail(err)
	}
	setReservedEnvironment(&ev, localTargetOs,
		"USERNAME", this.user.Name,
		"USERDOMAIN", host,
		"USERPROFILE", home,
		"HOMEDRIVE", filepath.VolumeName(home),
		"HOMEPATH", strings.TrimPrefix(home, filepath.VolumeName(home)),
	)

	return &cmd, &ev, release, nil
}

func hasWindowsPath(env sys.EnvVars) bool {
	for name := range env {
		if strings.EqualFold(name, "PATH") {
			return true
		}
	}
	return false
}

func (this *local) configureShellCmd(t Task, cmd *exec.Cmd) error {
	var argSource *template.Strings
	var argName string

	rc := t.SshSession().RawCommand()
	if len(rc) > 0 {
		argSource = &this.repository.conf.ExecCommandPrefix
		argName = "execCommandPrefix"
	} else {
		argSource = &this.repository.conf.ShellCommand
		argName = "shellCommand"
	}

	args, err := this.evaluateCommand(t, argName, argSource)
	if err != nil {
		return err
	}

	cmd.Path = args[0]
	cmd.Args = append(args, rc)

	return nil
}

func (this *local) evaluateCommand(t Task, name string, tmpl *template.Strings) ([]string, error) {
	args, err := tmpl.Render(t)
	if err != nil {
		return nil, errors.Config.Newf("cannot evaluate environment's %s: %w", name, err)
	}
	if len(args) < 1 {
		args = []string{configuration.DefaultShell}
	}

	args[0], err = exec.LookPath(args[0])
	if err != nil {
		return nil, errors.Config.Newf("cannot evaluate environment's %s executable (%q): %w", name, args[0], err)
	}

	return args, nil
}

func (this *local) configureCmdForPty(_ *exec.Cmd, pty, tty *os.File) error {
	if err := syscall.SetNonblock(syscall.Handle(int(pty.Fd())), true); err != nil {
		return err
	}
	if err := syscall.SetNonblock(syscall.Handle(int(tty.Fd())), true); err != nil {
		return err
	}
	return nil
}

func (this *local) getPathEnv() string {
	if v := os.Getenv("PATH"); v != "" {
		return v
	}
	return `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`
}

func (this *local) startedProcessGroupID(_ *exec.Cmd) int {
	return 0
}

func (this *local) signal(cmd *exec.Cmd, _ int, logger log.Logger, signal essh.Signal) {
	err := signalProcessFromSsh(signal, func(sig sys.Signal) error {
		native, err := sig.Native()
		if err != nil {
			return err
		}
		return cmd.Process.Signal(native)
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

func (this *local) kill(cmd *exec.Cmd, _ int, logger log.Logger) {
	if err := cmd.Process.Kill(); errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.EINVAL) {
		// Ignored.
	} else if err != nil {
		logger.WithError(err).
			With("pid", cmd.Process.Pid).
			Warn("cannot kill process")
	}
}

func (this *local) dispose(ctx context.Context) (bool, error) {
	this.deferred = false
	if this.repository.coordinator != nil && this.session != nil && localSessionHasActiveConnections(this.session) {
		this.deferred = true
		return false, nil
	}
	if !this.deleteOnDispose && !this.killProcessesOnDispose {
		return true, nil
	}
	if this.session == nil {
		return false, errors.System.Newf("cannot clean up local account without a session")
	}
	if this.repository.coordinator == nil && (this.deleteOnDispose ||
		(this.killProcessesOnDispose && !this.token.ProcessesKilledOnDispose)) {
		return false, errors.System.Newf("cannot clean up local account without a session coordinator")
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
		return false, err
	}
	var lt localToken
	if err := json.Unmarshal(stored, &lt); err != nil || lt.Version != 2 ||
		lt.User.SID != this.user.SID || lt.DeleteOnDispose != this.deleteOnDispose ||
		lt.KillProcessesOnDispose != this.killProcessesOnDispose || lt.AllowSystemUsers != this.allowSystemUsers {
		return false, errors.System.Newf("cannot verify local account token before cleanup: %v", err)
	}
	if lt.ProcessesKilledOnDispose {
		this.token.ProcessesKilledOnDispose = true
	}
	account := this.user
	if !this.accountMissing {
		account, err = localSAMCurrent(this.user.Name, this.user.SID, this.allowSystemUsers)
		if err != nil {
			account, err = lookupLocalWindowsAccountByUID(this.user.SID)
			if errors.Is(err, errLocalWindowsAccountNotFound) {
				if (this.deleteOnDispose && this.deleteProfileOnDispose) ||
					(this.killProcessesOnDispose && !this.token.ProcessesKilledOnDispose) {
					this.accountMissing = true
					account = this.user
				} else {
					return true, nil
				}
			}
		}
		if err != nil {
			if !this.accountMissing {
				return false, err
			}
		}
		if localSAMProtectedAccount(account) && !this.allowSystemUsers {
			return false, errors.System.Newf("local account %q is protected", account.Name)
		}
	} else if localSAMProtectedAccount(account) && !this.allowSystemUsers {
		return false, errors.System.Newf("local account %q is protected", account.Name)
	}
	if this.killProcessesOnDispose && !this.token.ProcessesKilledOnDispose {
		ready, err := this.repository.coordinator.canKillProcesses(ctx, this.session, account.Name, account.SID)
		if err != nil {
			return false, err
		}
		if !ready {
			this.deferred = true
			return false, nil
		}
		if err := localWindowsKillUserProcesses(ctx, account, this.allowSystemUsers); err != nil {
			return false, err
		}
		lt.ProcessesKilledOnDispose = true
		encoded, err := json.Marshal(&lt)
		if err != nil {
			return false, err
		}
		if err := updateLocalCleanupToken(ctx, this.session, stored, encoded); err != nil {
			return false, err
		}
		this.token.ProcessesKilledOnDispose = true
	}
	if this.repository.coordinator != nil && localSessionHasActiveConnections(this.session) {
		this.deferred = true
		return true, nil
	}
	if !this.deleteOnDispose {
		return true, nil
	}
	if this.accountMissing && !this.deleteProfileOnDispose {
		return true, nil
	}
	active, err := this.repository.coordinator.otherActive(ctx, this.session, account.Name, account.SID)
	if err != nil {
		return false, err
	}
	if active {
		this.deferred = true
		return false, nil
	}
	if !this.accountMissing {
		if err := DeleteLocalWindowsAccount(account.Name, account.SID, this.allowSystemUsers); err != nil {
			return false, err
		}
		this.accountMissing = true
	}
	if this.deleteProfileOnDispose {
		if err := deleteLocalWindowsProfile(account.SID); err != nil {
			return false, err
		}
	}
	return true, nil
}

func deleteLocalWindowsProfile(uid string) error {
	sid, err := windows.UTF16PtrFromString(uid)
	if err != nil {
		return err
	}
	proc := windows.NewLazySystemDLL("userenv.dll").NewProc("DeleteProfileW")
	if err := proc.Find(); err != nil {
		return err
	}
	ok, _, callErr := proc.Call(uintptr(unsafe.Pointer(sid)), 0, 0)
	if ok == 0 && !errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return localS4UCallError(callErr)
	}
	return nil
}
