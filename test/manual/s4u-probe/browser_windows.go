//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	clibase "github.com/echocat/cli4g"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/term"

	"github.com/engity-com/bifroest/pkg/audit"
	bcli "github.com/engity-com/bifroest/pkg/cli"
	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

const browserFixturePath = `C:\smoke\browser-fixture.json`
const browserMarkerName = "bifroest-browser-marker.txt"

func requireBrowserContainer() error {
	if os.Getenv("BIFROEST_TEST_SERVERCORE_BROWSER") != "1" {
		return fmt.Errorf("owned Server Core browser fixture was not enabled")
	}
	sid, err := currentSID()
	if err != nil || sid != "S-1-5-93-2-1" {
		return fmt.Errorf("browser bootstrap requires ContainerAdministrator, never a host identity: %s: %v", sid, err)
	}
	marker, err := os.ReadFile(`C:\smoke\servercore-container.marker`)
	if err != nil || strings.TrimSpace(string(marker)) != "bifroest-servercore-integration" {
		return fmt.Errorf("owned Server Core image marker is missing: %v", err)
	}
	return nil
}

func createBrowserDirectory(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(name, sa)
}

func copyBrowserExecutable(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	return errors.Join(copyErr, out.Close())
}

func browserPrivateKey(path string) (bfcrypto.PrivateKey, error) {
	return (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(rand.Reader, path)
}

func writeBrowserPrivateFile(path string, raw []byte) error {
	file, err := bfcrypto.CreateProtectedTempFile(filepath.Dir(path), ".browser-secret-*", 0400)
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func prepareBrowserConfiguration(binary string) (browserfixture.Fixture, error) {
	var fixture browserfixture.Fixture
	if err := requireBrowserContainer(); err != nil {
		return fixture, err
	}
	user, err := prepareContainerTestUser()
	if err != nil {
		return fixture, err
	}
	host, err := os.Hostname()
	if err != nil {
		return fixture, err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+user)
	if err != nil || sid == nil || kind != windows.SidTypeUser || !strings.EqualFold(domain, host) {
		return fixture, fmt.Errorf("new local browser account is unavailable: %v", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fixture, err
	}
	service := "bifroest-browser-" + hex.EncodeToString(nonce[:])
	base := os.Getenv("ProgramData")
	if base == "" {
		return fixture, fmt.Errorf("ProgramData is not set")
	}
	root := filepath.Join(base, service)
	// Public executable access is a separate sibling, never inherited by keys,
	// configuration, session tokens, audit journals or recordings.
	bin := root + "-bin"
	if err := createBrowserDirectory(bin, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;"+sid.String()+")"); err != nil {
		return fixture, err
	}
	self, err := os.Executable()
	if err != nil {
		return fixture, err
	}
	probe := filepath.Join(bin, "probe.exe")
	if err := copyBrowserExecutable(self, probe); err != nil {
		return fixture, err
	}
	if err := copyBrowserExecutable(binary, filepath.Join(bin, "bifroest.exe")); err != nil {
		return fixture, err
	}
	return prepareBrowserStateAsSystem(browserfixture.Fixture{Service: service, Root: root, User: user, SID: sid.String(), Probe: probe})
}

func initializeSystemBrowserState(fixture browserfixture.Fixture) (browserfixture.Fixture, error) {
	current, err := currentSID()
	if err != nil || current != "S-1-5-18" {
		return fixture, fmt.Errorf("private fixture files require container LocalSystem")
	}
	root, user, sid := fixture.Root, fixture.User, fixture.SID
	if err := createBrowserDirectory(root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		return fixture, err
	}
	hostKey, err := browserPrivateKey(filepath.Join(root, "host-key"))
	if err != nil {
		return fixture, err
	}
	auditKey, err := browserPrivateKey(filepath.Join(root, "audit-key"))
	if err != nil {
		return fixture, err
	}
	identity, err := audit.NewIdentity(auditKey)
	if err != nil {
		return fixture, err
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fixture, err
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned Windows browser fixture"}, DNSNames: []string{"app.example.org"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, tlsKey.Public(), tlsKey)
	if err != nil {
		return fixture, err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return fixture, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeBrowserPrivateFile(filepath.Join(root, "tls-cert"), cert); err != nil {
		return fixture, err
	}
	if err := writeBrowserPrivateFile(filepath.Join(root, "tls-key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})); err != nil {
		return fixture, err
	}
	public, err := os.ReadFile(`C:\smoke\browser-authorized-key`)
	if err != nil {
		return fixture, err
	}
	if err := os.WriteFile(filepath.Join(root, "authorized-key"), public, 0600); err != nil {
		return fixture, err
	}
	configuration := browserConfiguration(root, user, sid)
	if err := os.WriteFile(filepath.Join(root, "configuration.yaml"), []byte(configuration), 0600); err != nil {
		return fixture, err
	}
	fixture.Producer, fixture.Certificate, fixture.HostKey = identity.ProducerId().String(), string(cert), string(ssh.MarshalAuthorizedKey(hostKey.PublicKey().ToSsh()))
	return fixture, nil
}

func browserConfiguration(root, user, sid string) string {
	return fmt.Sprintf(`startMessage: '{{""}}'
ssh:
  addresses: ["0.0.0.0:2222"]
  keys:
    hostKeys: [%q]
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
  idleTimeout: 30s
  maxTimeout: 2m
  gracefulShutdownTimeout: 3s
session:
  type: fs
  storage: %q
  maxConnections: 4
  idleTimeout: 2m
  maxTimeout: 5m
auditlog:
  - name: default
    enabled: true
    identityFile: %q
    directory: %q
    minimumFreeBytes: 1048576
    recording:
      enabled: true
      directory: %q
      maximumSpoolBytes: 16777216
      retainFor: 1h
      targets: false
http:
  enabled: true
  addresses: ["0.0.0.0:8443"]
  domains: [app.example.org]
  tls:
    certificates:
      - certificateFile: %q
        privateKeyFile: %q
flows:
  - name: %s
    discoverAsSlug: Work
    auditlog: default
    authorization:
      type: local
      authorizedKeys: [%q]
      password:
        allowed: false
        interactiveAllowed: false
    environment:
      type: local
      name: %q
      uid: %q
      createIfAbsent: false
      updateIfDifferent: false
      deleteOnDispose: false
      killProcessesOnDispose: false
      deleteHomeTogetherWithUser: false
      portForwardingAllowed: false
      shellCommand: ['C:\Windows\System32\cmd.exe', /D, /Q]
      execCommandPrefix: ['C:\Windows\System32\cmd.exe', /D, /Q, /C]
      banner: '{{""}}'
`, filepath.Join(root, "host-key"), filepath.Join(root, "sessions"), filepath.Join(root, "audit-key"), filepath.Join(root, "auditlog"), filepath.Join(root, "recordings"), filepath.Join(root, "tls-cert"), filepath.Join(root, "tls-key"), browserfixture.Flow, filepath.Join(root, "authorized-key"), user, sid)
}

func browserServiceArguments(fixture browserfixture.Fixture) []string {
	return []string{"run", "--configuration=" + filepath.Join(fixture.Root, "configuration.yaml"), "--windowsService", "--serviceName=" + fixture.Service}
}

// Parse exactly the real service CLI, but never call service.Run, bind a port,
// provision an environment or register a Windows service. This is only a test
// controller preflight; the acceptance path below still starts the real binary.
func preflightBrowserService(fixture browserfixture.Fixture) (resultErr error) {
	app, err := bcli.NewApplication[clibase.NoOptions](nil, "native browser CLI preflight", nil).Create()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, app.Close()) }()
	invocation, err := app.Parse(context.Background(), &clibase.ParseOpts{Profiles: []string{cliCommon.ProfileExecutable}}, browserServiceArguments(fixture)...)
	if err != nil {
		return fmt.Errorf("native browser service CLI preflight: %w", err)
	}
	return invocation.Close()
}

func browserServiceStartDiagnostics(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	application, _ := exec.CommandContext(ctx, "wevtutil", "qe", "Application", "/q:*[System[Provider[@Name='"+name+"'] or Provider[@Name='engity-bifroest']]]", "/f:xml", "/c:20", "/rd:true").CombinedOutput()
	connection, endpointErr := net.DialTimeout("tcp", "127.0.0.1:8443", 250*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	return fmt.Sprintf("own/default Bifroest application events: %s; native HTTPS listener present=%t", application, endpointErr == nil)
}

// Runs only inside the existing marked Server Core LocalSystem probe service.
// Version/help never starts a gateway, creates sessions or authenticates a user.
func browserSystemStartupDiagnostics() string {
	service, serviceErr := svc.IsWindowsService()
	sid, sidErr := currentSID()
	var report strings.Builder
	fmt.Fprintf(&report, "BROWSER_SYSTEM_DIAGNOSTICS_BEGIN\nserviceDetector=%t detectorError=%v processSID=%s sidError=%v\n", service, serviceErr, sid, sidErr)
	if self, err := os.Executable(); err == nil {
		if descriptor, err := windows.GetNamedSecurityInfo(self, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
			owner, _, err := descriptor.Owner()
			fmt.Fprintf(&report, "controllerCreatedFileOwner=%v ownerError=%v\n", owner, err)
		}
		if file, err := bfcrypto.CreateProtectedTempFile(filepath.Dir(self), ".system-owner-*", 0600); err == nil {
			descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
			if err == nil {
				owner, _, ownerErr := descriptor.Owner()
				fmt.Fprintf(&report, "systemCreatedFileOwner=%v ownerError=%v\n", owner, ownerErr)
			}
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}
	for _, key := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "USERNAME"} {
		fmt.Fprintf(&report, "%s=%q\n", key, os.Getenv(key))
	}
	for _, args := range [][]string{{"version"}, {"run", "--help"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		raw, err := exec.CommandContext(ctx, `C:\smoke\bifroest.exe`, args...).CombinedOutput()
		cancel()
		fmt.Fprintf(&report, "binaryArgs=%q error=%v output=%s\n", args, err, raw)
	}
	report.WriteString("BROWSER_SYSTEM_DIAGNOSTICS_END\n")
	return report.String()
}

func serveBrowserContainer(binary string) (resultErr error) {
	fixture, err := prepareBrowserConfiguration(binary)
	if err != nil {
		return err
	}
	if err := preflightBrowserService(fixture); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.CreateService(fixture.Service, filepath.Join(filepath.Dir(fixture.Probe), "bifroest.exe"), mgr.Config{StartType: mgr.StartManual, ServiceStartName: "LocalSystem"}, browserServiceArguments(fixture)...)
	if err != nil {
		return err
	}
	defer service.Close()
	stopped := true
	defer func() {
		if stopped {
			_ = service.Delete()
			_ = eventlog.Remove(fixture.Service)
		}
	}()
	if err := eventlog.InstallAsEventCreate(fixture.Service, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return fmt.Errorf("start owned native Windows service: %w; %s", err, browserServiceStartDiagnostics(fixture.Service))
	}
	stopped = false
	raw, err := json.Marshal(fixture)
	if err != nil {
		return err
	}
	if err := writeBrowserPrivateFile(browserFixturePath, raw); err != nil {
		return err
	}
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			stopped = true
			if status.Win32ExitCode != 0 || status.ServiceSpecificExitCode != 0 {
				log, _ := exec.Command("wevtutil", "qe", "Application", "/q:*[System[Provider[@Name='"+fixture.Service+"']]]", "/f:text", "/c:20", "/rd:true").CombinedOutput()
				return fmt.Errorf("browser service failed: %d/%d: %s", status.Win32ExitCode, status.ServiceSpecificExitCode, log)
			}
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, _ = service.Control(svc.Stop)
	return fmt.Errorf("owned browser service exceeded fixture lifetime")
}

func readBrowserFixture() (browserfixture.Fixture, error) {
	var fixture browserfixture.Fixture
	if err := requireBrowserContainer(); err != nil {
		return fixture, err
	}
	raw, err := os.ReadFile(browserFixturePath)
	if err != nil {
		return fixture, err
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return fixture, err
	}
	if !strings.HasPrefix(fixture.Service, "bifroest-browser-") || len(fixture.Service) != len("bifroest-browser-")+32 {
		return fixture, fmt.Errorf("not an owned browser service")
	}
	return fixture, nil
}

func stopBrowserContainer() (resultErr error) {
	fixture, err := readBrowserFixture()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(fixture.Service)
	if err != nil {
		return err
	}
	defer service.Close()
	_, err = service.Control(svc.Stop)
	return err
}

func browserProbe(marker, write string) (browserfixture.Probe, error) {
	sid, err := currentSID()
	if err != nil {
		return browserfixture.Probe{}, err
	}
	profile := os.Getenv("USERPROFILE")
	if profile == "" {
		return browserfixture.Probe{}, fmt.Errorf("native user profile is unavailable")
	}
	file := filepath.Join(profile, browserMarkerName)
	if write != "" {
		if err := os.WriteFile(file, []byte(write), 0600); err != nil {
			return browserfixture.Probe{}, err
		}
	}
	content, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return browserfixture.Probe{}, err
	}
	pty := term.IsTerminal(int(os.Stdout.Fd()))
	var mode uint32
	stdoutError := ""
	if err := windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode); err != nil {
		stdoutError = err.Error()
	}
	console, consoleColumns, consoleRows := false, 0, 0
	consolePath, _ := windows.UTF16PtrFromString("CONOUT$")
	if handle, err := windows.CreateFile(consolePath, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
		console = true
		consoleColumns, consoleRows, _ = term.GetSize(int(handle))
		_ = windows.CloseHandle(handle)
	}
	cols, rows := 0, 0
	if pty {
		cols, rows, err = term.GetSize(int(os.Stdout.Fd()))
		if err != nil {
			return browserfixture.Probe{}, err
		}
	}
	return browserfixture.Probe{Marker: marker, Session: os.Getenv("BIFROEST_SESSION_ID"), Connection: os.Getenv("BIFROEST_CONNECTION_ID"), Execution: os.Getenv("BIFROEST_EXECUTION_ID"), SID: sid, User: os.Getenv("USERNAME"), Profile: profile, PID: os.Getpid(), Pty: pty, Columns: cols, Rows: rows, Content: string(content), Term: os.Getenv("TERM"), StdinPty: term.IsTerminal(int(os.Stdin.Fd())), StdoutError: stdoutError, Console: console, ConsoleColumns: consoleColumns, ConsoleRows: consoleRows}, nil
}

func printBrowserProbe(marker, write string) error {
	probe, err := browserProbe(marker, write)
	if err != nil {
		return err
	}
	line, err := browserfixture.Encode(probe)
	if err != nil {
		return err
	}
	_, err = fmt.Println(line)
	return err
}

func runBrowserProbe(args []string) error {
	switch {
	case len(args) == 1 && args[0] == "browser-events":
		fixture, err := readBrowserFixture()
		if err != nil {
			return err
		}
		_, err = fmt.Println(browserServiceStartDiagnostics(fixture.Service))
		return err
	case len(args) == 1 && args[0] == "browser-inspect":
		fixture, err := readBrowserFixture()
		if err != nil {
			return err
		}
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+fixture.SID, registry.QUERY_VALUE)
		if err != nil {
			return err
		}
		defer key.Close()
		profile, _, err := key.GetStringValue("ProfileImagePath")
		if err != nil {
			return err
		}
		content, err := os.ReadFile(filepath.Join(profile, browserMarkerName))
		if err != nil {
			return err
		}
		_, err = fmt.Print(string(content))
		return err
	case (len(args) == 2 || len(args) == 3) && args[0] == "browser-probe":
		write := ""
		if len(args) == 3 {
			write = args[2]
		}
		return printBrowserProbe(args[1], write)
	case len(args) == 4 && args[0] == "browser-size":
		cols, err := strconv.Atoi(args[1])
		if err != nil {
			return err
		}
		rows, err := strconv.Atoi(args[2])
		if err != nil {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			x, y, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				return err
			}
			if x == cols && y == rows {
				return printBrowserProbe(args[3], "")
			}
			time.Sleep(20 * time.Millisecond)
		}
		return fmt.Errorf("native ConPTY did not reach %dx%d", cols, rows)
	case len(args) == 1 && args[0] == "browser-hold":
		if err := printBrowserProbe("ssh-initial", "ssh-owned"); err != nil {
			return err
		}
		scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 4096))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "exit" {
				return nil
			}
			if !strings.HasPrefix(line, "check ") || len(line) > 80 {
				return fmt.Errorf("invalid held SSH probe command")
			}
			if err := printBrowserProbe(strings.TrimPrefix(line, "check "), ""); err != nil {
				return err
			}
		}
		return scanner.Err()
	default:
		return fmt.Errorf("unknown browser probe mode")
	}
}
