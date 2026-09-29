//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	gos "os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const (
	darwinServiceLabel              = "com.engity.bifroest"
	darwinServicePlist              = "/Library/LaunchDaemons/" + darwinServiceLabel + ".plist"
	darwinServiceBinary             = "/Library/PrivilegedHelperTools/" + darwinServiceLabel
	darwinServiceStateDirectory     = "/Library/Application Support/Engity/Bifroest"
	darwinServiceLogDirectory       = "/Library/Logs/Engity/Bifroest"
	darwinServiceSystemTarget       = "system/" + darwinServiceLabel
	darwinServiceExecutablePath     = "/usr/bin:/bin:/usr/sbin:/sbin"
	darwinServiceStandardOutputPath = darwinServiceLogDirectory + "/stdout.log"
	darwinServiceStandardErrorPath  = darwinServiceLogDirectory + "/stderr.log"
	darwinServiceConfigurationRef   = darwinServiceStateDirectory + "/service-configuration"
	darwinServiceLockPath           = "/Library/PrivilegedHelperTools/." + darwinServiceLabel + ".lock"
	darwinServiceLaunchctl          = "/bin/launchctl"
	darwinServicePlutil             = "/usr/bin/plutil"
	darwinServiceLs                 = "/bin/ls"
)

type darwinService struct{}

var _ = registerCommand(func(app *kingpin.Application) {
	svcCmd := app.Command("service", "")
	var conf configuration.Ref
	var svc darwinService

	start := true
	installCmd := svcCmd.Command("install", "Installs the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.install(conf, start)
		})
	registerConfigurationFlag(installCmd, &conf)
	installCmd.Flag("start", "If enabled, the service will be started afterwards, automatically. (Default=true)").
		BoolVar(&start)

	svcCmd.Command("remove", "Removes the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.remove()
		})

	svcCmd.Command("start", "Starts the service.").
		Action(func(*kingpin.ParseContext) error { return svc.start() })
	svcCmd.Command("stop", "Stops the service.").
		Action(func(*kingpin.ParseContext) error { return svc.stop() })
})

func (darwinService) install(conf configuration.Ref, start bool) error {
	if err := requireDarwinServiceRoot(); err != nil {
		return err
	}
	if err := conf.MakeAbsolute(); err != nil {
		return err
	}
	configurationFilename := conf.GetFilename()
	sourceBinary, err := gos.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own executable: %w", err)
	}
	if err := validateDarwinServiceBinary(sourceBinary); err != nil {
		return err
	}
	for _, directory := range []struct {
		path string
		mode gos.FileMode
	}{
		{filepath.Dir(darwinServiceBinary), 0755},
		{darwinServiceStateDirectory, 0750},
		{darwinServiceLogDirectory, 0710},
	} {
		if err := ensureSecureDarwinServiceDirectory(directory.path, directory.mode); err != nil {
			return err
		}
	}
	if err := validateDarwinServiceConfiguration(configurationFilename); err != nil {
		return err
	}
	lock, err := acquireDarwinServiceLock()
	if err != nil {
		return err
	}
	defer lock.release()

	stagedBinary, err := stageDarwinServiceFile(sourceBinary, darwinServiceBinary, 0755)
	if err != nil {
		return err
	}
	defer func() { _ = gos.Remove(stagedBinary) }()
	stagedPlist, err := stageDarwinServiceBytes(darwinServicePlistContents(configurationFilename), darwinServicePlist, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = gos.Remove(stagedPlist) }()
	encodedConfigurationFilename, err := json.Marshal(configurationFilename)
	if err != nil {
		return err
	}
	stagedConfigurationRef, err := stageDarwinServiceBytes(append(encodedConfigurationFilename, '\n'), darwinServiceConfigurationRef, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = gos.Remove(stagedConfigurationRef) }()
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	if _, err := runDarwinServiceCommandContext(ctx, darwinServicePlutil, "-lint", stagedPlist); err != nil {
		return err
	}

	wasLoaded, err := darwinServiceLoadedContext(ctx)
	if err != nil {
		return err
	}
	deployment := darwinServiceDeployment{
		wasLoaded: wasLoaded,
		files: []darwinServiceDeploymentFile{
			{target: darwinServiceBinary, staged: stagedBinary},
			{target: darwinServicePlist, staged: stagedPlist},
			{target: darwinServiceConfigurationRef, staged: stagedConfigurationRef},
		},
	}
	committed := false
	defer func() {
		if !committed {
			_ = deployment.rollback()
		}
	}()
	if err := stopDarwinServiceContext(ctx); err != nil {
		return deployment.fail(err)
	}
	if err := deployment.replace(); err != nil {
		return deployment.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return deployment.fail(fmt.Errorf("service installation interrupted: %w", err))
	}
	if start {
		if err := startDarwinServiceContext(ctx, configurationFilename); err != nil {
			return deployment.fail(err)
		}
	}
	if err := ctx.Err(); err != nil {
		return deployment.fail(fmt.Errorf("service installation interrupted: %w", err))
	}
	stopSignals()
	deployment.commit()
	committed = true
	return nil
}

func (darwinService) remove() error {
	if err := requireDarwinServiceRoot(); err != nil {
		return err
	}
	lock, err := acquireDarwinServiceLock()
	if err != nil {
		return err
	}
	defer lock.release()
	if err := stopDarwinService(); err != nil {
		return err
	}
	for _, filename := range []string{darwinServicePlist, darwinServiceBinary} {
		if err := gos.Remove(filename); err != nil && !gos.IsNotExist(err) {
			return err
		}
	}
	fmt.Fprintf(gos.Stdout, "Preserved configuration and state in %s\n", darwinServiceStateDirectory)
	fmt.Fprintf(gos.Stdout, "Preserved logs in %s\n", darwinServiceLogDirectory)
	return nil
}

func (darwinService) start() error {
	if err := requireDarwinServiceRoot(); err != nil {
		return err
	}
	lock, err := acquireDarwinServiceLock()
	if err != nil {
		return err
	}
	defer lock.release()
	configurationFilename, err := installedDarwinServiceConfiguration()
	if err != nil {
		return err
	}
	return startDarwinService(configurationFilename)
}

func startDarwinService(configurationFilename string) error {
	return startDarwinServiceContext(context.Background(), configurationFilename)
}

func startDarwinServiceContext(ctx context.Context, configurationFilename string) error {
	if err := validateDarwinServiceConfiguration(configurationFilename); err != nil {
		return err
	}
	loaded, err := darwinServiceLoadedContext(ctx)
	if err != nil {
		return err
	}
	if loaded {
		_, err = runDarwinServiceCommandContext(ctx, darwinServiceLaunchctl, "kickstart", darwinServiceSystemTarget)
	} else {
		_, err = runDarwinServiceCommandContext(ctx, darwinServiceLaunchctl, "bootstrap", "system", darwinServicePlist)
	}
	return err
}

func (darwinService) stop() error {
	if err := requireDarwinServiceRoot(); err != nil {
		return err
	}
	lock, err := acquireDarwinServiceLock()
	if err != nil {
		return err
	}
	defer lock.release()
	return stopDarwinService()
}

func stopDarwinService() error {
	return stopDarwinServiceContext(context.Background())
}

func stopDarwinServiceContext(ctx context.Context) error {
	loaded, err := darwinServiceLoadedContext(ctx)
	if err != nil || !loaded {
		return err
	}
	_, err = runDarwinServiceCommandContext(ctx, darwinServiceLaunchctl, "bootout", darwinServiceSystemTarget)
	return err
}

func requireDarwinServiceRoot() error {
	if gos.Geteuid() != 0 {
		return fmt.Errorf("bifröst service management must run as root")
	}
	return nil
}

func validateDarwinServiceBinary(filename string) error {
	info, err := gos.Stat(filename)
	if err != nil {
		return fmt.Errorf("cannot access Bifröst binary %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("bifröst binary is not an executable regular file: %s", filename)
	}
	return nil
}

func validateDarwinServiceConfiguration(filename string) error {
	relative, err := filepath.Rel(darwinServiceStateDirectory, filename)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("configuration must be located below %s", darwinServiceStateDirectory)
	}
	for directory := filepath.Dir(filename); ; directory = filepath.Dir(directory) {
		if err := validateSecureDarwinServiceDirectory(directory, 0750); err != nil {
			return err
		}
		if directory == darwinServiceStateDirectory {
			break
		}
	}
	info, err := gos.Lstat(filename)
	if err != nil {
		return fmt.Errorf("cannot access configuration %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("configuration is not a regular file: %s", filename)
	}
	if err := validateDarwinServiceOwnershipAndMode(filename, info, 0137); err != nil {
		return fmt.Errorf("insecure configuration: %w", err)
	}
	return nil
}

func ensureSecureDarwinServiceDirectory(path string, mode gos.FileMode) error {
	info, err := gos.Lstat(path)
	if gos.IsNotExist(err) {
		if err := validateNearestDarwinServiceAncestor(path); err != nil {
			return err
		}
		if err := gos.MkdirAll(path, mode); err != nil {
			return err
		}
		if err := gos.Chown(path, 0, 0); err != nil {
			return err
		}
		if err := gos.Chmod(path, mode); err != nil {
			return err
		}
		info, err = gos.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	if err := validateDarwinServiceOwnershipAndMode(path, info, 0022); err != nil {
		return fmt.Errorf("insecure service directory: %w", err)
	}
	if info.Mode().Perm()&0700 != mode&0700 {
		return fmt.Errorf("service directory owner permissions are too restrictive: %s", path)
	}
	if err := gos.Chmod(path, info.Mode().Perm()&mode); err != nil {
		return err
	}
	return validateDarwinServicePathAncestors(path)
}

func validateNearestDarwinServiceAncestor(path string) error {
	for current := filepath.Dir(filepath.Clean(path)); current != string(filepath.Separator); current = filepath.Dir(current) {
		if _, err := gos.Lstat(current); gos.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		return validateDarwinServicePathAncestors(current)
	}
	return nil
}

func validateSecureDarwinServiceDirectory(path string, maximumMode gos.FileMode) error {
	info, err := gos.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	forbidden := gos.FileMode(0777) &^ maximumMode
	if err := validateDarwinServiceOwnershipAndMode(path, info, forbidden); err != nil {
		return fmt.Errorf("insecure service directory: %w", err)
	}
	return nil
}

func validateDarwinServicePathAncestors(path string) error {
	for current := filepath.Clean(path); current != string(filepath.Separator); current = filepath.Dir(current) {
		info, err := gos.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("expected directory: %s", current)
		}
		if err := validateDarwinServiceOwnershipAndModeWithGroup(current, info, 0022, false); err != nil {
			return fmt.Errorf("insecure service directory ancestor: %w", err)
		}
	}
	return nil
}

func validateDarwinServiceOwnershipAndMode(path string, info gos.FileInfo, forbidden gos.FileMode) error {
	return validateDarwinServiceOwnershipAndModeWithGroup(path, info, forbidden, true)
}

func validateDarwinServiceOwnershipAndModeWithGroup(path string, info gos.FileInfo, forbidden gos.FileMode, requireWheel bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect ownership of %s", path)
	}
	if stat.Uid != 0 || requireWheel && stat.Gid != 0 || info.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("%s has insecure ownership or permissions", path)
	}
	if err := validateDarwinServiceNoAcl(path); err != nil {
		return err
	}
	return nil
}

func validateDarwinServiceNoAcl(path string) error {
	listing, err := runDarwinServiceCommand(darwinServiceLs, "-lde", path)
	if err != nil {
		return err
	}
	fields := strings.Fields(listing)
	if len(fields) == 0 || strings.Contains(fields[0], "+") {
		return fmt.Errorf("%s must not have an access-control list", path)
	}
	return nil
}

func installedDarwinServiceConfiguration() (string, error) {
	info, err := gos.Lstat(darwinServiceConfigurationRef)
	if err != nil {
		return "", fmt.Errorf("cannot access installed service configuration reference: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("installed service configuration reference is not a regular file")
	}
	if err := validateDarwinServiceOwnershipAndMode(darwinServiceConfigurationRef, info, 0177); err != nil {
		return "", err
	}
	raw, err := gos.ReadFile(darwinServiceConfigurationRef)
	if err != nil {
		return "", err
	}
	var filename string
	if err := json.Unmarshal(raw, &filename); err != nil {
		return "", fmt.Errorf("invalid installed service configuration reference: %w", err)
	}
	if filename == "" {
		return "", fmt.Errorf("installed service configuration reference is empty")
	}
	return filename, nil
}

type darwinServiceLock struct {
	file *gos.File
}

func acquireDarwinServiceLock() (*darwinServiceLock, error) {
	if err := ensureSecureDarwinServiceDirectory(filepath.Dir(darwinServiceLockPath), 0755); err != nil {
		return nil, err
	}
	if err := validateDarwinServicePathAncestors(filepath.Dir(darwinServiceLockPath)); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(darwinServiceLockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := gos.NewFile(uintptr(fd), darwinServiceLockPath)
	fail := func(err error) (*darwinServiceLock, error) {
		_ = file.Close()
		return nil, err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fail(err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0077 != 0 {
		return fail(fmt.Errorf("service lock has insecure type, ownership or permissions: %s", darwinServiceLockPath))
	}
	if err := validateDarwinServiceNoAcl(darwinServiceLockPath); err != nil {
		return fail(err)
	}
	if err := syscall.Fchmod(fd, 0600); err != nil {
		return fail(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fail(err)
	}
	return &darwinServiceLock{file: file}, nil
}

func (this *darwinServiceLock) release() {
	_ = syscall.Flock(int(this.file.Fd()), syscall.LOCK_UN)
	_ = this.file.Close()
}

func stageDarwinServiceFile(source, target string, mode gos.FileMode) (string, error) {
	input, err := gos.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { _ = input.Close() }()
	return stageDarwinServiceReader(input, target, mode)
}

func stageDarwinServiceBytes(source []byte, target string, mode gos.FileMode) (string, error) {
	return stageDarwinServiceReader(bytes.NewReader(source), target, mode)
}

func stageDarwinServiceReader(source io.Reader, target string, mode gos.FileMode) (_ string, rErr error) {
	file, err := gos.CreateTemp(filepath.Dir(target), filepath.Base(target)+".new.*")
	if err != nil {
		return "", err
	}
	filename := file.Name()
	defer func() {
		if rErr != nil {
			_ = gos.Remove(filename)
		}
	}()
	if _, err := io.Copy(file, source); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := gos.Chown(filename, 0, 0); err != nil {
		return "", err
	}
	if err := gos.Chmod(filename, mode); err != nil {
		return "", err
	}
	return filename, nil
}

type darwinServiceDeployment struct {
	files     []darwinServiceDeploymentFile
	wasLoaded bool
	finished  bool
}

type darwinServiceDeploymentFile struct {
	target      string
	staged      string
	backup      string
	hadOriginal bool
	installed   bool
}

func (this *darwinServiceDeployment) replace() error {
	for i := range this.files {
		file := &this.files[i]
		if _, err := gos.Lstat(file.target); err == nil {
			backup, err := reserveDarwinServiceFilename(file.target, ".previous.*")
			if err != nil {
				return err
			}
			file.backup = backup
			if err := gos.Rename(file.target, file.backup); err != nil {
				return err
			}
			file.hadOriginal = true
		} else if !gos.IsNotExist(err) {
			return err
		}
		if err := gos.Rename(file.staged, file.target); err != nil {
			return err
		}
		file.installed = true
	}
	return nil
}

func (this *darwinServiceDeployment) fail(cause error) error {
	rollbackErr := this.rollback()
	if rollbackErr != nil {
		return fmt.Errorf("%w; cannot restore previous service installation: %v", cause, rollbackErr)
	}
	return cause
}

func (this *darwinServiceDeployment) rollback() error {
	if this.finished {
		return nil
	}
	this.finished = true
	var failures []string
	if _, err := runDarwinServiceCommand(darwinServiceLaunchctl, "bootout", darwinServiceSystemTarget); err != nil {
		loaded, checkErr := darwinServiceLoaded()
		if checkErr != nil || loaded {
			failures = append(failures, err.Error())
		}
	}
	for i := len(this.files) - 1; i >= 0; i-- {
		file := &this.files[i]
		if file.installed {
			if err := gos.Remove(file.target); err != nil && !gos.IsNotExist(err) {
				failures = append(failures, err.Error())
			}
		}
		if file.hadOriginal {
			if err := gos.Rename(file.backup, file.target); err != nil {
				failures = append(failures, err.Error())
			}
		}
	}
	if this.wasLoaded {
		if _, err := runDarwinServiceCommand(darwinServiceLaunchctl, "bootstrap", "system", darwinServicePlist); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

func (this *darwinServiceDeployment) commit() {
	this.finished = true
	for i := range this.files {
		if backup := this.files[i].backup; backup != "" {
			_ = gos.Remove(backup)
		}
	}
}

func reserveDarwinServiceFilename(target, suffix string) (string, error) {
	file, err := gos.CreateTemp(filepath.Dir(target), filepath.Base(target)+suffix)
	if err != nil {
		return "", err
	}
	filename := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := gos.Remove(filename); err != nil {
		return "", err
	}
	return filename, nil
}

func darwinServiceLoaded() (bool, error) {
	return darwinServiceLoadedContext(context.Background())
}

func darwinServiceLoadedContext(ctx context.Context) (bool, error) {
	command := exec.CommandContext(ctx, darwinServiceLaunchctl, "print", darwinServiceSystemTarget)
	command.Env = darwinServiceCommandEnvironment()
	if err := command.Run(); err == nil {
		return true, nil
	} else if ctx.Err() != nil {
		return false, ctx.Err()
	} else if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 113 {
		return false, nil
	} else {
		return false, err
	}
}

func runDarwinServiceCommand(executable string, args ...string) (string, error) {
	return runDarwinServiceCommandContext(context.Background(), executable, args...)
}

func runDarwinServiceCommandContext(ctx context.Context, executable string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = darwinServiceCommandEnvironment()
	output, err := command.CombinedOutput()
	plain := strings.TrimSpace(string(output))
	if err != nil {
		return plain, fmt.Errorf("%s %s failed: %w: %s", executable, strings.Join(args, " "), err, plain)
	}
	return plain, nil
}

func darwinServiceCommandEnvironment() []string {
	return []string{"HOME=/var/root", "PATH=" + darwinServiceExecutablePath}
}

func darwinServicePlistContents(configurationFilename string) []byte {
	escape := func(value string) string {
		var result bytes.Buffer
		_ = xml.EscapeText(&result, []byte(value))
		return result.String()
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>run</string>
        <string>--configuration=%s</string>
        <string>--log.colorMode=never</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>%s</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ExitTimeOut</key>
    <integer>60</integer>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>Umask</key>
    <integer>23</integer>
</dict>
</plist>
`,
		escape(darwinServiceLabel),
		escape(darwinServiceBinary),
		escape(configurationFilename),
		escape(darwinServiceStateDirectory),
		escape(darwinServiceExecutablePath),
		escape(darwinServiceStandardOutputPath),
		escape(darwinServiceStandardErrorPath),
	))
}
