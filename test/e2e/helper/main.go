//go:build e2e

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	creackpty "github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}

	switch args[0] {
	case "ready":
		fmt.Println("ready")
		return nil
	case "identity":
		return identity()
	case "environment":
		fmt.Printf("session=%s\nconnection=%s\n", os.Getenv("BIFROEST_SESSION_ID"), os.Getenv("BIFROEST_CONNECTION_ID"))
		time.Sleep(100 * time.Millisecond)
		return nil
	case "streams":
		fmt.Fprintln(os.Stdout, "stdout-e2e")
		fmt.Fprintln(os.Stderr, "stderr-e2e")
		time.Sleep(100 * time.Millisecond)
		os.Exit(23)
	case "pty":
		return pty()
	case "pty-size":
		if len(args) != 3 {
			return errors.New("usage: pty-size <columns> <rows>")
		}
		return ptySize(args[1], args[2])
	case "stream-duplex":
		if len(args) != 2 {
			return errors.New("usage: stream-duplex <bytes>")
		}
		return streamDuplex(args[1])
	case "signal":
		return captureSignal()
	case "echo-server":
		if len(args) != 3 {
			return errors.New("usage: echo-server <tcp|unix> <address>")
		}
		return echoServer(args[1], args[2])
	case "echo-client":
		return echoClient(args[1:])
	case "agent-keys":
		return agentKeys()
	case "wait-for-stop":
		if len(args) != 2 {
			return errors.New("usage: wait-for-stop <pid-file>")
		}
		return waitForStop(args[1])
	case "process-alive":
		if len(args) != 2 {
			return errors.New("usage: process-alive <pid-file>")
		}
		return processAlive(args[1])
	case "process-info":
		if len(args) != 2 {
			return errors.New("usage: process-info <pid-file>")
		}
		return processInfo(args[1])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}

func identity() error {
	current, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve current user: %w", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	values := [][2]string{
		{"uid", strconv.Itoa(os.Getuid())},
		{"name", current.Username},
		{"pwd", wd},
		{"HOME", os.Getenv("HOME")},
		{"USER", os.Getenv("USER")},
		{"SHELL", os.Getenv("SHELL")},
	}
	for _, value := range values {
		fmt.Printf("%s=%s\n", value[0], value[1])
	}
	return nil
}

func pty() error {
	info, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("stat stdin: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("stdin is not a character device")
	}
	fmt.Printf("pty=true term=%s\n", os.Getenv("TERM"))
	time.Sleep(100 * time.Millisecond)
	return nil
}

func ptySize(columnsArg, rowsArg string) error {
	columns, err := strconv.ParseUint(columnsArg, 10, 16)
	if err != nil || columns == 0 {
		return fmt.Errorf("invalid PTY columns %q", columnsArg)
	}
	rows, err := strconv.ParseUint(rowsArg, 10, 16)
	if err != nil || rows == 0 {
		return fmt.Errorf("invalid PTY rows %q", rowsArg)
	}
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)
	defer signal.Stop(resized)

	deadline := time.Now().Add(2 * time.Second)
	var initial creackpty.Winsize
	for {
		size, err := creackpty.GetsizeFull(os.Stdin)
		if err != nil {
			return fmt.Errorf("get PTY size: %w", err)
		}
		initial = *size
		if size.Cols == uint16(columns) && size.Rows == uint16(rows) {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("initial PTY size is %dx%d, want %dx%d", size.Cols, size.Rows, columns, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
	printPtySize(initial)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-resized:
			current, err := creackpty.GetsizeFull(os.Stdin)
			if err != nil {
				return fmt.Errorf("get resized PTY size: %w", err)
			}
			if current.Cols != initial.Cols || current.Rows != initial.Rows {
				printPtySize(*current)
				return nil
			}
		case <-timer.C:
			return errors.New("timed out waiting for PTY resize")
		}
	}
}

func printPtySize(size creackpty.Winsize) {
	fmt.Printf("size=%dx%d\n", size.Cols, size.Rows)
}

func streamDuplex(sizeArg string) error {
	size, err := parseSize(sizeArg)
	if err != nil {
		return err
	}
	payload := testPayload(size)
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, bytes.NewReader(payload))
		writeDone <- err
	}()

	input := make([]byte, size)
	if _, err := io.ReadFull(os.Stdin, input); err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if !bytes.Equal(input, payload) {
		return errors.New("input payload mismatch")
	}
	var extra [1]byte
	if n, err := os.Stdin.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected input EOF, got n=%d err=%v", n, err)
	}
	if err := <-writeDone; err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Println("ok")
	return nil
}

func captureSignal() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	defer signal.Stop(signals)
	fmt.Println("ready")
	select {
	case received := <-signals:
		fmt.Printf("signal=%s\n", received)
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("timed out waiting for SIGUSR1")
	}
}

func echoServer(network, address string) error {
	if network != "tcp" && network != "unix" {
		return fmt.Errorf("unsupported network %q", network)
	}
	if network == "unix" {
		if err := os.Remove(address); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	defer listener.Close()
	fmt.Println(listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func echoClient(args []string) error {
	if len(args) < 3 {
		return errors.New("usage: echo-client <tcp|unix> <address> <bytes> OR echo-client socks <proxy> <target> <bytes>")
	}

	var conn net.Conn
	var sizeArg string
	var err error
	switch args[0] {
	case "tcp", "unix":
		if len(args) != 3 {
			return errors.New("usage: echo-client <tcp|unix> <address> <bytes>")
		}
		conn, err = net.DialTimeout(args[0], args[1], 3*time.Second)
		sizeArg = args[2]
	case "socks":
		if len(args) != 4 {
			return errors.New("usage: echo-client socks <proxy> <target> <bytes>")
		}
		conn, err = dialSOCKS5(args[1], args[2])
		sizeArg = args[3]
	default:
		return fmt.Errorf("unsupported client network %q", args[0])
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	size, err := parseSize(sizeArg)
	if err != nil {
		return err
	}
	payload := testPayload(size)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("echo mismatch: sent %d bytes, received %d", len(payload), len(response))
	}
	fmt.Printf("ok %d\n", size)
	return nil
}

func parseSize(value string) (int, error) {
	size, err := strconv.Atoi(value)
	if err != nil || size < 1 || size > 8*1024*1024 {
		return 0, fmt.Errorf("invalid byte count %q", value)
	}
	return size, nil
}

func testPayload(size int) []byte {
	seed := []byte("bifroest-e2e\x00\xff")
	return bytes.Repeat(seed, size/len(seed)+1)[:size]
}

func dialSOCKS5(proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fail(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fail(err)
	}
	if response[0] != 5 || response[1] != 0 {
		return fail(fmt.Errorf("SOCKS5 authentication rejected: %v", response))
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fail(err)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		request = append(request, 1)
		request = append(request, ip.To4()...)
	} else {
		if len(host) > 255 {
			return fail(errors.New("SOCKS5 host name is too long"))
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fail(err)
	}
	if header[0] != 5 || header[1] != 0 {
		return fail(fmt.Errorf("SOCKS5 connect rejected with status %d", header[1]))
	}
	var addressLength int
	switch header[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fail(err)
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	default:
		return fail(fmt.Errorf("invalid SOCKS5 address type %d", header[3]))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return fail(err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return conn, nil
}

func agentKeys() error {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return errors.New("SSH_AUTH_SOCK is empty")
	}
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return fmt.Errorf("connect to forwarded agent: %w", err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil {
		return fmt.Errorf("list agent keys: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("forwarded agent contains no keys")
	}
	for _, key := range keys {
		publicKey, err := ssh.ParsePublicKey(key.Blob)
		if err != nil {
			return fmt.Errorf("parse agent key: %w", err)
		}
		challenge := []byte("bifroest-e2e-agent-signature")
		signature, err := client.Sign(publicKey, challenge)
		if err != nil {
			return fmt.Errorf("sign with agent key: %w", err)
		}
		if err := publicKey.Verify(challenge, signature); err != nil {
			return fmt.Errorf("verify agent signature: %w", err)
		}
		fmt.Print(string(ssh.MarshalAuthorizedKey(publicKey)))
	}
	time.Sleep(100 * time.Millisecond)
	return nil
}

func waitForStop(pidFile string) error {
	if err := os.MkdirAll(filepath.Dir(pidFile), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
	return nil
}

func processAlive(pidFile string) error {
	pid, err := readPID(pidFile)
	if err != nil {
		return err
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return err
	}
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		fields := strings.Fields(string(stat))
		if len(fields) >= 3 && fields[2] == "Z" {
			return errors.New("process is a zombie")
		}
	}
	return nil
}

func processInfo(pidFile string) error {
	pid, err := readPID(pidFile)
	if err != nil {
		return err
	}
	for _, name := range []string{"status", "cmdline", "environ"} {
		content, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
		if readErr != nil {
			fmt.Printf("%s: %v\n", name, readErr)
			continue
		}
		fmt.Printf("--- %s ---\n%s\n", name, strings.ReplaceAll(string(content), "\x00", "\n"))
	}
	return nil
}

func readPID(pidFile string) (int, error) {
	content, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(content)))
}
