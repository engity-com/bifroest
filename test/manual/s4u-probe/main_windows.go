//go:build windows

// This is a manual, privileged feasibility probe, not part of Bifroest's runtime.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const targetUser = "foosel"

var (
	secur32       = windows.NewLazySystemDLL("secur32.dll")
	registerLogon = secur32.NewProc("LsaRegisterLogonProcess")
	lookupPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	logonUser     = secur32.NewProc("LsaLogonUser")
	deregister    = secur32.NewProc("LsaDeregisterLogonProcess")
	freeBuffer    = secur32.NewProc("LsaFreeReturnBuffer")
	allocateLUID  = windows.NewLazySystemDLL("advapi32.dll").NewProc("AllocateLocallyUniqueId")
)

type lsaString struct {
	Length, MaximumLength uint16
	Buffer                *byte
}

type unicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type s4uLogon struct {
	MessageType uint32
	Flags       uint32
	User        unicodeString
	Domain      unicodeString
}

type luid struct {
	Low  uint32
	High int32
}

type tokenSource struct {
	Name [8]byte
	ID   luid
}

type containerTestUserInfo struct {
	Name, Password    *uint16
	PasswordAge, Priv uint32
	HomeDir, Comment  *uint16
	Flags             uint32
	ScriptPath        *uint16
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "run":
		err = run("", targetUser, false)
	case len(os.Args) == 3 && os.Args[1] == "run-test":
		err = run(os.Args[2], targetUser, false)
	case len(os.Args) == 4 && os.Args[1] == "run-test":
		err = run(os.Args[2], os.Args[3], false)
	case len(os.Args) == 3 && os.Args[1] == "run-container-test":
		var account string
		account, err = prepareContainerTestUser()
		if err == nil {
			err = run(os.Args[2], account, true)
		}
	case len(os.Args) == 4 && os.Args[1] == "service":
		err = svc.Run(os.Args[2], &probeService{resultPath: os.Args[3]})
	case len(os.Args) == 6 && os.Args[1] == "service":
		err = svc.Run(os.Args[2], &probeService{resultPath: os.Args[3], testBinary: os.Args[4], user: os.Args[5]})
	case len(os.Args) == 7 && os.Args[1] == "service" && os.Args[6] == "servercore":
		err = svc.Run(os.Args[2], &probeService{resultPath: os.Args[3], testBinary: os.Args[4], user: os.Args[5], serverCore: true})
	case len(os.Args) == 2 && os.Args[1] == "child":
		var sid string
		sid, err = currentSID()
		if err == nil {
			fmt.Println(sid)
		}
	default:
		err = fmt.Errorf("usage: %s run | run-test <windows environment test binary> [local account] | run-container-test <windows environment test binary>", os.Args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func prepareContainerTestUser() (string, error) {
	if os.Getenv("BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER") != "1" {
		return "", fmt.Errorf("container-only test account creation was not explicitly enabled")
	}
	sid, err := currentSID()
	if err != nil {
		return "", err
	}
	if sid != "S-1-5-93-2-1" { // ContainerAdministrator, never the host Administrator.
		return "", fmt.Errorf("container test account creation requires ContainerAdministrator, got %s", sid)
	}
	add := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd")
	if err := add.Find(); err != nil {
		return "", fmt.Errorf("NetUserAdd unavailable in container: %w", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := "bif" + hex.EncodeToString(nonce[:])
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	username, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	password, err := windows.UTF16PtrFromString("T3st!" + hex.EncodeToString(secret[:]) + "X")
	if err != nil {
		return "", err
	}
	info := containerTestUserInfo{Name: username, Password: password, Priv: 1, Flags: 0x201} // USER_PRIV_USER, UF_SCRIPT | UF_NORMAL_ACCOUNT.
	var invalidParameter uint32
	status, _, _ := add.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&invalidParameter)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(password)
	if status != 0 {
		return "", fmt.Errorf("NetUserAdd: %w (parameter %d)", syscall.Errno(status), invalidParameter)
	}
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	accountSID, domain, kind, err := windows.LookupSID("", host+`\`+name)
	if err != nil || accountSID == nil || !accountSID.IsValid() || kind != windows.SidTypeUser || !strings.EqualFold(domain, host) {
		return "", fmt.Errorf("container test account %q is not a local SAM user: %v", name, err)
	}
	return name, nil
}

func run(testBinary, user string, serverCore bool) error {
	if user == "" || strings.ContainsAny(user, `\/@`) {
		return fmt.Errorf("expected a bare local account name")
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		return fmt.Errorf("ProgramData is not set")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "bifroest-s4u-probe-" + hex.EncodeToString(nonce[:])
	dir := filepath.Join(base, name)
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	account, domain, kind, err := windows.LookupSID("", host+`\`+user)
	if err != nil || kind != windows.SidTypeUser || !strings.EqualFold(domain, host) {
		return fmt.Errorf("cannot resolve local test account %q on %q: %v", user, host, err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;" + account.String() + ")")
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	dirName, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(dirName, sa); err != nil {
		return fmt.Errorf("create protected probe directory: %w", err)
	}
	stopped := true
	defer func() {
		if !stopped {
			fmt.Fprintln(os.Stderr, "service may still be running; retained probe directory:", dir)
			return
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "cannot remove probe output:", err)
		}
	}()

	source, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	exe := filepath.Join(dir, "probe.exe")
	exeName, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(exeName, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("create protected probe executable: %w", err)
	}
	out := os.NewFile(uintptr(handle), exe)
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if testBinary != "" {
		tests, err := os.Open(testBinary)
		if err != nil {
			return err
		}
		defer tests.Close()
		testBinary = filepath.Join(dir, "environment.test.exe")
		testName, err := windows.UTF16PtrFromString(testBinary)
		if err != nil {
			return err
		}
		testHandle, err := windows.CreateFile(testName, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return err
		}
		testFile := os.NewFile(uintptr(testHandle), testBinary)
		_, copyErr := io.Copy(testFile, tests)
		closeErr := testFile.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
	}
	resultPath := filepath.Join(dir, "result.txt")
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("SCM access (run from an elevated Windows account): %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	args := []string{"service", name, resultPath}
	if testBinary != "" {
		args = append(args, testBinary, user)
		if serverCore {
			args = append(args, "servercore")
		}
	}
	s, err := m.CreateService(name, exe, mgr.Config{
		StartType:        mgr.StartManual,
		ServiceStartName: "LocalSystem",
	}, args...)
	if err != nil {
		return fmt.Errorf("create temporary service: %w", err)
	}
	defer s.Close()
	defer func() {
		if !stopped {
			fmt.Fprintln(os.Stderr, "temporary service may still be running; retained:", name)
			return
		}
		if err := s.Delete(); err != nil {
			fmt.Fprintf(os.Stderr, "cannot delete temporary service %s: %v\n", name, err)
		}
	}()

	fmt.Println("temporary service:", name)
	stopped = false
	if err := s.Start(); err != nil {
		if status, queryErr := s.Query(); queryErr == nil && status.State == svc.Stopped {
			stopped = true
		}
		return fmt.Errorf("start temporary service: %w", err)
	}
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("query temporary service: %w", err)
		}
		if status.State == svc.Stopped {
			stopped = true
			result, err := os.ReadFile(resultPath)
			if err != nil {
				return fmt.Errorf("service stopped (exit code %d), no result: %w", status.Win32ExitCode, err)
			}
			if status.Win32ExitCode != 0 {
				return fmt.Errorf("service failed (exit code %d): %s", status.Win32ExitCode, strings.TrimSpace(string(result)))
			}
			if !strings.HasPrefix(string(result), "PASS ") {
				return fmt.Errorf("probe failed: %s", strings.TrimSpace(string(result)))
			}
			fmt.Print(string(result))
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("temporary service %s did not stop within 180s; check and stop it before removing the executable", name)
}

type probeService struct {
	resultPath string
	testBinary string
	user       string
	serverCore bool
}

func (p *probeService) Execute(_ []string, _ <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running}
	var err error
	result := "PASS local S4U child process has foosel's SID\n"
	if p.testBinary != "" {
		pattern := "TestLocalWindows(S4ULogonAsUser|RunAsUser|ConPTYAsUser)$"
		if p.serverCore {
			pattern = "^(TestLocalWindows(S4ULogonAsUser|RunAsUser|ConPTYAsUser|ConPTYDistinguishesShellExitFromRelayFailure)|TestLocalServerCore(ProviderAccountLifecycle|FailedUpdateRestoresManagedMembership|ProvisioningPrecedesSessionDispose|FailedSkelDisablesNewAccount|FailedDisplayDisablesNewAccount|UnmanagedNewAccountCanBeDisabled|ProcessCleanupWaitsForExit))$"
		}
		cmd := exec.Command(p.testBinary, "-test.run="+pattern, "-test.v", "-test.timeout=150s")
		cmd.Env = append(os.Environ(), "BIFROEST_TEST_LOCAL_WINDOWS_USER="+p.user)
		if p.serverCore {
			cmd.Env = append(cmd.Env, "BIFROEST_TEST_SERVERCORE_IN_CONTAINER=1")
		}
		output, runErr := cmd.CombinedOutput()
		err = runErr
		if err == nil {
			required := []string{"TestLocalWindowsS4ULogonAsUser", "TestLocalWindowsRunAsUser", "TestLocalWindowsConPTYAsUser"}
			if p.serverCore {
				required = append(required, "TestLocalWindowsConPTYDistinguishesShellExitFromRelayFailure", "TestLocalServerCoreProviderAccountLifecycle", "TestLocalServerCoreFailedUpdateRestoresManagedMembership", "TestLocalServerCoreProvisioningPrecedesSessionDispose", "TestLocalServerCoreFailedSkelDisablesNewAccount", "TestLocalServerCoreFailedDisplayDisablesNewAccount", "TestLocalServerCoreUnmanagedNewAccountCanBeDisabled", "TestLocalServerCoreProcessCleanupWaitsForExit")
			}
			for _, test := range required {
				if !strings.Contains(string(output), "--- PASS: "+test+" ") {
					err = fmt.Errorf("required test %s did not pass", test)
					break
				}
			}
		}
		result = "PASS local Windows integration tests:\n" + string(output)
	} else {
		err = probe()
	}
	if err != nil {
		if p.testBinary != "" {
			result = "FAIL " + err.Error() + ":\n" + strings.TrimPrefix(result, "PASS local Windows integration tests:\n")
		} else {
			result = "FAIL " + err.Error() + "\n"
		}
	}
	if writeErr := os.WriteFile(p.resultPath, []byte(result), 0600); writeErr != nil {
		return false, 2
	}
	if err != nil {
		return false, 1
	}
	return false, 0
}

func probe() error {
	actual, err := currentSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if actual != system.String() {
		return fmt.Errorf("service runs as %s, not LocalSystem", actual)
	}

	host, err := os.Hostname()
	if err != nil {
		return err
	}
	expected, domain, _, err := windows.LookupSID("", host+`\`+targetUser)
	if err != nil {
		return fmt.Errorf("lookup local user %s: %w", targetUser, err)
	}
	if !strings.EqualFold(domain, host) {
		return fmt.Errorf("account resolved in %q, not local machine %q", domain, host)
	}

	token, err := s4uToken(".", targetUser)
	if err != nil {
		return err
	}
	defer token.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(token, 0, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer primary.Close()
	tokenUser, err := primary.GetTokenUser()
	if err != nil {
		return err
	}
	if got := tokenUser.User.Sid.String(); got != expected.String() {
		return fmt.Errorf("S4U token SID %s, expected %s", got, expected)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "child")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(primary)}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CreateProcessAsUser/child: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if got := strings.TrimSpace(string(output)); got != expected.String() {
		return fmt.Errorf("child SID %s, expected %s", got, expected)
	}
	return nil
}

func currentSID() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func s4uToken(host, user string) (windows.Token, error) {
	var handle uintptr
	origin, originBytes := makeLSAString("BifS4U")
	var mode uint64
	status, _, _ := registerLogon.Call(uintptr(unsafe.Pointer(&origin)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&mode)))
	runtime.KeepAlive(originBytes)
	if err := ntError("LsaRegisterLogonProcess", status); err != nil {
		return 0, err
	}
	defer func() { _, _, _ = deregister.Call(handle) }()

	packageName, packageBytes := makeLSAString("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")
	var packageID uint32
	status, _, _ = lookupPackage.Call(handle, uintptr(unsafe.Pointer(&packageName)), uintptr(unsafe.Pointer(&packageID)))
	runtime.KeepAlive(packageBytes)
	if err := ntError("LsaLookupAuthenticationPackage", status); err != nil {
		return 0, err
	}

	auth, authSize := makeS4UBuffer(user, host)
	source := tokenSource{}
	copy(source.Name[:], "BifS4U")
	ok, _, callErr := allocateLUID.Call(uintptr(unsafe.Pointer(&source.ID)))
	if ok == 0 {
		return 0, fmt.Errorf("AllocateLocallyUniqueId: %w", callErr)
	}
	var profile uintptr
	var profileSize uint32
	var logonID luid
	var token windows.Token
	var quota [8]uint64 // Larger than QUOTA_LIMITS on windows/amd64.
	var substatus uint32
	status, _, _ = logonUser.Call(
		handle,
		uintptr(unsafe.Pointer(&origin)),
		3, // Network S4U returns an impersonation token; DuplicateTokenEx converts it.
		uintptr(packageID),
		uintptr(unsafe.Pointer(&auth[0])),
		uintptr(authSize),
		0,
		uintptr(unsafe.Pointer(&source)),
		uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileSize)),
		uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(&quota[0])),
		uintptr(unsafe.Pointer(&substatus)),
	)
	runtime.KeepAlive(auth)
	if profile != 0 {
		_, _, _ = freeBuffer.Call(profile)
	}
	if err := ntError("LsaLogonUser", status); err != nil {
		if token != 0 {
			token.Close()
		}
		return 0, fmt.Errorf("%w (substatus 0x%08x)", err, substatus)
	}
	return token, nil
}

func makeLSAString(s string) (lsaString, []byte) {
	b := append([]byte(s), 0)
	return lsaString{uint16(len(b) - 1), uint16(len(b)), &b[0]}, b
}

func makeS4UBuffer(user, domain string) ([]uint64, int) {
	u := utf16.Encode([]rune(user))
	d := utf16.Encode([]rune(domain))
	size := int(unsafe.Sizeof(s4uLogon{}))
	domainOffset := size + (len(u)+1)*2
	length := domainOffset + (len(d)+1)*2
	buffer := make([]uint64, (length+7)/8)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buffer[0])), len(buffer)*8)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[size+i*2:], v)
	}
	for i, v := range d {
		binary.LittleEndian.PutUint16(b[domainOffset+i*2:], v)
	}
	msg := (*s4uLogon)(unsafe.Pointer(&buffer[0]))
	msg.MessageType = 12 // MsV1_0S4ULogon
	msg.User = unicodeString{uint16(len(u) * 2), uint16((len(u) + 1) * 2), (*uint16)(unsafe.Pointer(&b[size]))}
	msg.Domain = unicodeString{uint16(len(d) * 2), uint16((len(d) + 1) * 2), (*uint16)(unsafe.Pointer(&b[domainOffset]))}
	return buffer, length
}

func ntError(operation string, status uintptr) error {
	if uint32(status) != 0 {
		return fmt.Errorf("%s: NTSTATUS 0x%08x", operation, uint32(status))
	}
	return nil
}
