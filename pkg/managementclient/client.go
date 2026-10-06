package managementclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/management"
)

type Target struct {
	Host         string
	User         string
	Port         uint16
	ExplicitPort bool
}

type settings struct {
	host       string
	user       string
	port       uint16
	identities []string
	agentPath  string
	knownHosts []string
}

func resolve(target Target) (settings, error) {
	lookup := func(key string) (string, error) { return ssh_config.GetStrict(target.Host, key) }
	host, err := lookup("HostName")
	if err != nil {
		return settings{}, err
	}
	if host == "" {
		host = target.Host
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n%") {
		return settings{}, fmt.Errorf("unsupported SSH HostName %q", host)
	}
	for _, key := range []string{"ProxyJump", "ProxyCommand"} {
		value, err := lookup(key)
		if err != nil {
			return settings{}, err
		}
		if value != "" && value != "none" {
			return settings{}, fmt.Errorf("SSH %s is not supported by the integrated management client", key)
		}
	}
	user := target.User
	if user == "" {
		user, err = lookup("User")
		if err != nil {
			return settings{}, err
		}
	}
	if user == "" {
		current, err := osuser.Current()
		if err != nil {
			return settings{}, err
		}
		user = current.Username
	}
	port := target.Port
	if !target.ExplicitPort {
		configured, err := lookup("Port")
		if err != nil {
			return settings{}, err
		}
		if configured != "" {
			number, err := strconv.ParseUint(configured, 10, 16)
			if err != nil || number == 0 {
				return settings{}, fmt.Errorf("invalid SSH Port %q", configured)
			}
			port = uint16(number)
		}
	}
	if port == 0 {
		port = 22
	}
	identities, err := ssh_config.GetAllStrict(target.Host, "IdentityFile")
	if err != nil {
		return settings{}, err
	}
	if len(identities) == 0 || len(identities) == 1 && identities[0] == "~/.ssh/identity" {
		identities = []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"}
	}
	agentPath, err := lookup("IdentityAgent")
	if err != nil {
		return settings{}, err
	}
	knownHostsConfig, err := lookup("UserKnownHostsFile")
	if err != nil {
		return settings{}, err
	}
	if knownHostsConfig == "" {
		knownHostsConfig = "~/.ssh/known_hosts"
	}
	knownHosts := make([]string, 0)
	for _, candidate := range strings.Fields(knownHostsConfig) {
		path, err := expandHome(candidate)
		if err != nil {
			return settings{}, err
		}
		if _, err := os.Stat(path); err == nil {
			knownHosts = append(knownHosts, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return settings{}, err
		}
	}
	if len(knownHosts) == 0 {
		return settings{}, fmt.Errorf("no SSH known_hosts file found for %q", target.Host)
	}
	return settings{host: host, user: user, port: port, identities: identities, agentPath: agentPath, knownHosts: knownHosts}, nil
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}

type limitedOutput struct{ bytes.Buffer }

func (this *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > management.MaxWireResultBytes-this.Len() {
		return 0, fmt.Errorf("management response exceeds %d bytes", management.MaxWireResultBytes)
	}
	return this.Buffer.Write(p)
}

func Run(ctx context.Context, target Target, args []string, output io.Writer) (rErr error) {
	if len(args) < 2 {
		return fmt.Errorf("a management command and subcommand are required")
	}
	format, wireArgs, err := selectOutputFormat(args)
	if err != nil {
		return err
	}
	if len(wireArgs) < 2 || wireArgs[0] != "flow" && wireArgs[0] != "session" && wireArgs[0] != "auditlog" {
		return fmt.Errorf("remote command %q is not yet supported", args[0])
	}
	for _, arg := range wireArgs {
		if arg == "-c" || arg == "--configuration" || strings.HasPrefix(arg, "--configuration=") {
			return fmt.Errorf("local --configuration cannot be combined with a remote target")
		}
		if arg == "--decryptionIdentityFile" || strings.HasPrefix(arg, "--decryptionIdentityFile=") || arg == "--source" || strings.HasPrefix(arg, "--source=") {
			return fmt.Errorf("offline source and local decryption identities cannot be used as remote command arguments")
		}
	}
	conf, err := resolve(target)
	if err != nil {
		return err
	}
	hostKeys, err := knownhosts.New(conf.knownHosts...)
	if err != nil {
		return err
	}
	auth := make([]ssh.AuthMethod, 0, 2)
	if agentClient, closer, err := connectAgent(conf.agentPath); err == nil && agentClient != nil {
		if closer != nil {
			defer func() { rErr = errors.Join(rErr, closer.Close()) }()
		}
		auth = append(auth, ssh.PublicKeysCallback(agentClient.Signers))
	} else if conf.agentPath != "" && conf.agentPath != "none" {
		return fmt.Errorf("cannot connect to configured SSH agent: %w", err)
	}
	var signers []ssh.Signer
	for _, name := range conf.identities {
		path, err := expandHome(name)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		signer, err := ssh.ParsePrivateKey(content)
		if err != nil {
			var passphrase *ssh.PassphraseMissingError
			if errors.As(err, &passphrase) && len(auth) > 0 {
				continue
			}
			return fmt.Errorf("cannot use SSH identity %q: %w", path, err)
		}
		signers = append(signers, signer)
	}
	if len(signers) != 0 {
		auth = append(auth, ssh.PublicKeys(signers...))
	}
	if len(auth) == 0 {
		return fmt.Errorf("no SSH agent or usable identity file available")
	}
	address := net.JoinHostPort(conf.host, strconv.Itoa(int(conf.port)))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	clientConn, chans, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: conf.user, Auth: auth, HostKeyCallback: hostKeys})
	if err != nil {
		return err
	}
	client := ssh.NewClient(clientConn, chans, requests)
	defer func() { _ = client.Close() }()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	encoded, err := management.EncodeWireRequest(wireArgs)
	if err != nil {
		return err
	}
	session.Stdin = bytes.NewReader(encoded)
	var stdout limitedOutput
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run(management.WireCommand); err != nil {
		return fmt.Errorf("remote management command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	switch wireArgs[0] + " " + wireArgs[1] {
	case "auditlog ls":
		var entries []management.AuditlogSummary
		if err := management.DecodeWireResult(&stdout, &entries); err != nil {
			return err
		}
		return management.WriteAuditlogList(output, format, entries)
	case "auditlog show":
		var settings map[string]any
		if err := management.DecodeWireResult(&stdout, &settings); err != nil {
			return err
		}
		return management.WriteFlowSettings(output, format, settings)
	case "auditlog events":
		var records []audit.VerifiedRecord
		if err := management.DecodeWireResult(&stdout, &records); err != nil {
			return err
		}
		return management.WriteAuditEvents(output, format, records, management.AuditEventFilter{}, containsArg(args, "--with-sensitive"))
	case "flow ls":
		var entries []management.FlowSummary
		if err := management.DecodeWireResult(&stdout, &entries); err != nil {
			return err
		}
		return management.WriteFlowList(output, format, entries)
	case "flow show":
		var settings map[string]any
		if err := management.DecodeWireResult(&stdout, &settings); err != nil {
			return err
		}
		return management.WriteFlowSettings(output, format, settings)
	case "session ls":
		var entries []management.SessionView
		if err := management.DecodeWireResult(&stdout, &entries); err != nil {
			return err
		}
		return management.WriteSessionList(output, format, entries)
	case "session show":
		var entry management.SessionView
		if err := management.DecodeWireResult(&stdout, &entry); err != nil {
			return err
		}
		return management.WriteSessionDetail(output, format, entry)
	default:
		return fmt.Errorf("unsupported management command %q", strings.Join(wireArgs[:2], " "))
	}
}

func containsArg(args []string, candidate string) bool {
	for _, arg := range args {
		if arg == candidate {
			return true
		}
	}
	return false
}

func selectOutputFormat(args []string) (management.Format, []string, error) {
	format := management.FormatTable
	selected := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--format":
			index++
			if index >= len(args) {
				return "", nil, fmt.Errorf("--format requires a value")
			}
			format = management.Format(args[index])
		case strings.HasPrefix(arg, "--format="):
			format = management.Format(strings.TrimPrefix(arg, "--format="))
		default:
			selected = append(selected, arg)
		}
	}
	if format != management.FormatTable && format != management.FormatJSON && format != management.FormatYAML {
		return "", nil, fmt.Errorf("invalid management output format %q", format)
	}
	return format, selected, nil
}
