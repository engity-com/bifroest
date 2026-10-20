package management

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	consoleKernel32    = windows.NewLazySystemDLL("kernel32.dll")
	readConsoleInput   = consoleKernel32.NewProc("ReadConsoleInputW")
	flushConsoleInput  = consoleKernel32.NewProc("FlushConsoleInputBuffer")
	cancelConsoleInput = consoleKernel32.NewProc("CancelSynchronousIo")
)

type consoleKeyEvent struct {
	down       int32
	repeat     uint16
	virtualKey uint16
	scanCode   uint16
	character  uint16
	control    uint32
}

// INPUT_RECORD's event union is 16 bytes, aligned after its WORD event type.
type consoleInputRecord struct {
	kind uint16
	key  consoleKeyEvent
}

type consoleInput struct {
	handle   windows.Handle
	original uint32
	echo     bool
	output   io.Writer
}

func openConsoleInput(input uintptr, echo bool, output io.Writer) (*consoleInput, error) {
	var handle windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(process, windows.Handle(input), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	fail := func(err error) (*consoleInput, error) {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return fail(err)
	}
	mode := original &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT |
		windows.ENABLE_MOUSE_INPUT | windows.ENABLE_WINDOW_INPUT | windows.ENABLE_VIRTUAL_TERMINAL_INPUT | windows.ENABLE_QUICK_EDIT_MODE)
	mode |= windows.ENABLE_EXTENDED_FLAGS
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		return fail(err)
	}
	return &consoleInput{handle: handle, original: original, echo: echo, output: output}, nil
}

func (this *consoleInput) close(discard bool) error {
	var flushErr error
	if discard {
		if success, _, err := flushConsoleInput.Call(uintptr(this.handle)); success == 0 {
			flushErr = err
		}
	}
	return errors.Join(flushErr, windows.SetConsoleMode(this.handle, this.original), windows.CloseHandle(this.handle))
}

func (this *consoleInput) nextRecord() (consoleInputRecord, error) {
	var record consoleInputRecord
	var count uint32
	success, _, err := readConsoleInput.Call(uintptr(this.handle), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(&record)
	runtime.KeepAlive(&count)
	if success == 0 {
		return record, err
	}
	return record, nil
}

func (this *consoleInput) readLine(ctx context.Context) (line []byte, resultErr error) {
	if err := cancelConsoleInput.Find(); err != nil {
		return nil, err
	}
	// CancelSynchronousIo targets a thread, not a handle. Keep all native reads
	// on this thread and join the cancellation worker before releasing it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return nil, err
	}
	finished, canceled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(canceled)
		select {
		case <-finished:
			return
		case <-ctx.Done():
		}
		for {
			// Retry if cancellation arrived just before a read was issued.
			_, _, _ = cancelConsoleInput.Call(uintptr(thread))
			select {
			case <-finished:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	defer func() {
		close(finished)
		<-canceled
		resultErr = errors.Join(resultErr, windows.CloseHandle(thread))
	}()
	defer func() {
		if resultErr != nil {
			clear(line)
			line = nil
		}
	}()
	line = make([]byte, 0, maximumConsoleInputBytes)
	var highSurrogate uint16
	for {
		if err := ctx.Err(); err != nil {
			return line, err
		}
		record, err := this.nextRecord()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return line, ctxErr
		}
		if err != nil {
			return line, err
		}
		if record.kind != 1 || record.key.down == 0 {
			continue
		}
		key := record.key
		for range max(int(key.repeat), 1) {
			switch {
			case key.character == 3:
				return line, context.Canceled
			case key.character == '\r' || key.character == '\n':
				if this.echo {
					if err := writeConsoleText(this.output, "\n"); err != nil {
						return line, err
					}
				}
				return line, nil
			case key.character == 4:
				return line, io.EOF
			case key.character == '\b':
				if len(line) != 0 {
					_, size := utf8.DecodeLastRune(line)
					clear(line[len(line)-size:])
					line = line[:len(line)-size]
					if this.echo {
						if err := writeConsoleText(this.output, "\b \b"); err != nil {
							return line, err
						}
					}
				}
				continue
			}
			value := rune(key.character)
			if 0xd800 <= key.character && key.character <= 0xdbff {
				highSurrogate = key.character
				continue
			}
			if 0xdc00 <= key.character && key.character <= 0xdfff {
				value = utf16.DecodeRune(rune(highSurrogate), value)
			}
			highSurrogate = 0
			if unicode.IsControl(value) {
				continue
			}
			if len(line)+utf8.RuneLen(value) > maximumConsoleInputBytes {
				return line, fmt.Errorf("SSH authentication input exceeds %d bytes", maximumConsoleInputBytes)
			}
			line = utf8.AppendRune(line, value)
			if this.echo {
				if err := writeConsoleText(this.output, string(value)); err != nil {
					return line, err
				}
			}
		}
	}
}
