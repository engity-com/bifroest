//go:build windows

package environment

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ReadLocalConPTYCommand reads the command before the relay begins receiving
// terminal input and resize frames on the same pipe.
func ReadLocalConPTYCommand(input io.Reader) ([]string, error) {
	var header [5]byte
	if _, err := io.ReadFull(input, header[:]); err != nil {
		return nil, fmt.Errorf("read ConPTY command frame: %w", err)
	}
	size := binary.LittleEndian.Uint32(header[1:])
	if header[0] != 'C' || size == 0 || size > 128*1024 {
		return nil, fmt.Errorf("invalid ConPTY command frame")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(input, payload); err != nil {
		return nil, fmt.Errorf("read ConPTY command: %w", err)
	}
	var argv []string
	if err := json.Unmarshal(payload, &argv); err != nil {
		return nil, fmt.Errorf("decode ConPTY command: %w", err)
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty ConPTY command")
	}
	return argv, nil
}

// RunLocalConPTYRelay runs argv in a pseudoconsole owned by the relay's user.
// Stdin carries framed data/resize/EOF requests; stdout carries only PTY output.
func RunLocalConPTYRelay(cols, rows int, argv []string) (int, error) {
	if cols < 1 || cols > 32767 || rows < 1 || rows > 32767 {
		return -1, fmt.Errorf("invalid ConPTY size %d x %d", cols, rows)
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) || strings.ContainsRune(argv[0], '"') {
		return -1, fmt.Errorf("invalid shell executable or argv[0]")
	}
	for _, arg := range argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return -1, fmt.Errorf("shell argument contains NUL")
		}
	}
	path, err := windows.UTF16PtrFromString(argv[0])
	if err != nil {
		return -1, fmt.Errorf("invalid shell executable: %w", err)
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return -1, fmt.Errorf("invalid shell command line: %w", err)
	}

	var inputRead, inputWrite, outputRead, outputWrite windows.Handle
	defer func() {
		for _, h := range []windows.Handle{inputRead, inputWrite, outputRead, outputWrite} {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
		}
	}()
	if err := windows.CreatePipe(&inputRead, &inputWrite, nil, 0); err != nil {
		return -1, fmt.Errorf("create ConPTY input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outputRead, &outputWrite, nil, 0); err != nil {
		return -1, fmt.Errorf("create ConPTY output pipe: %w", err)
	}
	var console windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, inputRead, outputWrite, 0, &console); err != nil {
		return -1, fmt.Errorf("create pseudoconsole: %w", err)
	}
	_ = windows.CloseHandle(inputRead)
	inputRead = 0
	_ = windows.CloseHandle(outputWrite)
	outputWrite = 0
	in := os.NewFile(uintptr(inputWrite), "conpty-input")
	inputWrite = 0
	out := os.NewFile(uintptr(outputRead), "conpty-output")
	outputRead = 0
	defer in.Close()
	defer out.Close()
	outputDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(os.Stdout, out)
		outputDone <- err
	}()
	// Closing a pseudoconsole may wait for its output pipe. Never close it on
	// the goroutine that must also drain that pipe.
	var consoleMu sync.Mutex
	consoleClosed := false
	closeConsole := func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			consoleMu.Lock()
			consoleClosed = true
			consoleMu.Unlock()
			windows.ClosePseudoConsole(console)
			close(done)
		}()
		return done
	}
	defer func() {
		consoleMu.Lock()
		closed := consoleClosed
		consoleMu.Unlock()
		if !closed {
			go in.Close()
			closedDone := closeConsole()
			if outputDone != nil {
				<-outputDone
			}
			<-closedDone
		}
	}()

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return -1, fmt.Errorf("allocate process attributes: %w", err)
	}
	defer attrs.Delete()
	// Update takes the PVOID handle value, not a pointer to the handle variable.
	value := *(*unsafe.Pointer)(unsafe.Pointer(&console))
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, value, unsafe.Sizeof(console)); err != nil {
		return -1, fmt.Errorf("attach pseudoconsole: %w", err)
	}
	startup := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	startup.Cb = uint32(unsafe.Sizeof(startup))

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return -1, fmt.Errorf("create shell job: %w", err)
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return -1, fmt.Errorf("configure shell job: %w", err)
	}

	var proc windows.ProcessInformation
	if err := windows.CreateProcess(path, line, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_SUSPENDED,
		nil, nil, &startup.StartupInfo, &proc); err != nil {
		return -1, fmt.Errorf("start shell: %w", err)
	}
	defer windows.CloseHandle(proc.Process)
	defer windows.CloseHandle(proc.Thread)
	// A suspended process cannot spawn children before joining the job.
	defer func() {
		_ = windows.TerminateJobObject(job, 1)
		_, _ = windows.WaitForSingleObject(proc.Process, windows.INFINITE)
	}()
	if err := windows.AssignProcessToJobObject(job, proc.Process); err != nil {
		_ = windows.TerminateProcess(proc.Process, 1)
		return -1, fmt.Errorf("assign shell to job: %w", err)
	}
	if _, err := windows.ResumeThread(proc.Thread); err != nil {
		return -1, fmt.Errorf("resume shell: %w", err)
	}

	inputDone := make(chan error, 1)
	go func() {
		var header [5]byte
		var data [32768]byte
		for {
			_, err := io.ReadFull(os.Stdin, header[:])
			if errors.Is(err, io.EOF) {
				inputDone <- in.Close()
				return
			}
			if err != nil {
				inputDone <- fmt.Errorf("read input frame: %w", err)
				return
			}
			n := binary.LittleEndian.Uint32(header[1:])
			switch header[0] {
			case 'D':
				if n > uint32(len(data)) {
					inputDone <- fmt.Errorf("oversized input frame: %d", n)
					return
				}
				if _, err = io.ReadFull(os.Stdin, data[:n]); err == nil && n != 0 {
					_, err = in.Write(data[:n])
				}
			case 'R':
				if n != 4 {
					inputDone <- fmt.Errorf("invalid resize frame length: %d", n)
					return
				}
				if _, err = io.ReadFull(os.Stdin, data[:4]); err == nil {
					w, h := binary.LittleEndian.Uint16(data[:2]), binary.LittleEndian.Uint16(data[2:4])
					if w == 0 || w > 32767 || h == 0 || h > 32767 {
						inputDone <- fmt.Errorf("invalid resize %d x %d", w, h)
						return
					}
					consoleMu.Lock()
					if !consoleClosed {
						err = windows.ResizePseudoConsole(console, windows.Coord{X: int16(w), Y: int16(h)})
					}
					consoleMu.Unlock()
				}
			case 'E':
				if n != 0 {
					inputDone <- fmt.Errorf("invalid EOF frame length: %d", n)
					return
				}
				if err := in.Close(); err != nil {
					inputDone <- err
					return
				}
				continue
			default:
				inputDone <- fmt.Errorf("unknown input frame kind %q", header[0])
				return
			}
			if err != nil {
				inputDone <- fmt.Errorf("relay ConPTY input: %w", err)
				return
			}
		}
	}()

	processDone := make(chan error, 1)
	go func() {
		status, err := windows.WaitForSingleObject(proc.Process, windows.INFINITE)
		if err == nil && status != windows.WAIT_OBJECT_0 {
			err = fmt.Errorf("unexpected shell wait result %d", status)
		}
		processDone <- err
	}()
	var relayErr error
	for processDone != nil {
		select {
		case err := <-inputDone:
			inputDone = nil
			if err != nil {
				relayErr = fmt.Errorf("relay input: %w", err)
				_ = windows.TerminateJobObject(job, 1)
			}
		case err := <-outputDone:
			outputDone = nil
			if err != nil {
				relayErr = fmt.Errorf("relay output: %w", err)
				_ = windows.TerminateJobObject(job, 1)
			}
		case err := <-processDone:
			processDone = nil
			if err != nil {
				relayErr = fmt.Errorf("wait for shell: %w", err)
			}
		}
	}
	var code uint32
	if err := windows.GetExitCodeProcess(proc.Process, &code); err != nil && relayErr == nil {
		relayErr = fmt.Errorf("get shell exit code: %w", err)
	}
	var accounting struct {
		TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime int64
		PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
	}
	if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil || accounting.ActiveProcesses > 0 {
		// The shell has exited; surviving descendants must not hold ConPTY open.
		_ = windows.TerminateJobObject(job, 1)
	}
	// The parent may keep the control pipe open after the shell has exited.
	// Cancel a pending frame read rather than waiting for another frame.
	_ = windows.CancelIoEx(windows.Handle(os.Stdin.Fd()), nil)
	go os.Stdin.Close()
	_ = windows.CancelIoEx(windows.Handle(in.Fd()), nil)
	go in.Close() // An in-flight synchronous write must not block output draining.
	closedDone := closeConsole()
	<-closedDone
	if outputDone != nil {
		if err := <-outputDone; err != nil && relayErr == nil {
			relayErr = fmt.Errorf("relay output: %w", err)
		}
	}
	if relayErr != nil {
		return -1, relayErr
	}
	return int(code), nil
}
