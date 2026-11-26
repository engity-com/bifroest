//go:build windows

package conpty

import (
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/sys"
)

// All process architectures are retained in the Windows binary and inventoried
// as shipped resources. Only the current process's DLL is ever extracted.
//
//go:embed assets/*/conpty.dll
var payloads embed.FS

type Library struct {
	dll                            *windows.DLL
	create, resize, release, close *windows.Proc
	directory                      string
	directoryFile, payloadFile     *os.File
}

// Load loads only the embedded, digest-pinned interface library. In particular,
// neither PATH/CWD overrides nor a fallback to kernel32's legacy close exist.
// The caller must finish all console operations before closing the library.
func Load() (*Library, error) {
	return LoadWithObservation(nil)
}

// LoadWithObservation is Load with optional passive operation milestones. The
// observer receives only fixed phase names, never paths, payloads or native data.
// It must not block or panic. Normal production callers use Load.
func LoadWithObservation(observe func(string)) (_ *Library, resultErr error) {
	phase := func(name string) {
		if observe != nil {
			observe(name)
		}
	}
	phase("library.begin")
	library := &Library{}
	defer func() {
		if resultErr != nil {
			phase("library.cleanup.begin")
			resultErr = errors.Join(resultErr, library.Close())
			phase("library.cleanup.returned")
		}
	}()
	var selected *Payload
	for _, payload := range Payloads {
		if payload.Arch == runtime.GOARCH {
			selected = &payload
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("unsupported ConPTY process architecture %s", runtime.GOARCH)
	}
	raw, err := payloads.ReadFile(selected.Filename())
	if err != nil {
		return nil, err
	}
	if err := selected.Verify(raw); err != nil {
		return nil, err
	}
	phase("library.payload.verified")
	parent, err := sys.CanonicalPath(os.TempDir())
	if err != nil {
		return nil, err
	}
	phase("library.temp.ready")
	phase("library.directory.begin")
	library.directory, err = bfcrypto.CreateProtectedTempDirectory(parent, "bifroest-conpty-*")
	if err != nil {
		return nil, fmt.Errorf("create private ConPTY directory: %w", err)
	}
	phase("library.directory.created")
	library.directoryFile, err = bfcrypto.EnsurePrivateDirectory(library.directory)
	if err != nil {
		return nil, err
	}
	phase("library.directory.locked")
	path := filepath.Join(library.directory, "conpty.dll")
	phase("library.bootstrap.begin")
	if err := bfcrypto.WriteBootstrapFile(path, raw, false); err != nil {
		return nil, err
	}
	phase("library.bootstrap.ready")
	phase("library.payload-lock.begin")
	library.payloadFile, err = lockPayload(path, *selected)
	if err != nil {
		return nil, err
	}
	phase("library.payload-lock.ready")
	// OpenConsole is deliberately absent. Microsoft's library selects the inbox
	// conhost by its System32 path, which also works without GUI DLLs on Nano.
	phase("library.load.begin")
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("load pinned ConPTY library: %w", err)
	}
	phase("library.load.ready")
	library.dll = &windows.DLL{Name: path, Handle: handle}
	for _, binding := range []struct {
		name   string
		target **windows.Proc
	}{
		{"ConptyCreatePseudoConsole", &library.create},
		{"ConptyResizePseudoConsole", &library.resize},
		{"ConptyReleasePseudoConsole", &library.release},
		{"ConptyClosePseudoConsole", &library.close},
	} {
		*binding.target, err = library.dll.FindProc(binding.name)
		if err != nil {
			return nil, fmt.Errorf("resolve pinned ConPTY export %s: %w", binding.name, err)
		}
	}
	phase("library.ready")
	return library, nil
}

func lockPayload(path string, payload Payload) (*os.File, error) {
	name, err := sys.WindowsPathPointer(path)
	if err != nil {
		return nil, err
	}
	// Disallow writes, renames and deletion until all console operations and
	// FreeLibrary have completed. Check ACL/link safety and digest under the lock.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	raw, err := bfcrypto.ReadSecurePrivateFile(path, 2<<20)
	if err == nil {
		err = payload.Verify(raw)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (l *Library) Close() error {
	if l.dll != nil {
		if err := l.dll.Release(); err != nil {
			return err
		}
		l.dll = nil
	}
	var result error
	if l.payloadFile != nil {
		result = errors.Join(result, l.payloadFile.Close())
		l.payloadFile = nil
	}
	if l.directoryFile != nil {
		result = errors.Join(result, l.directoryFile.Close())
		l.directoryFile = nil
	}
	if l.directory != "" {
		if err := os.Remove(filepath.Join(l.directory, "conpty.dll")); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
		if err := os.Remove(l.directory); err != nil {
			result = errors.Join(result, err)
		}
		l.directory = ""
	}
	return result
}

func packedSize(size windows.Coord) uintptr {
	return uintptr(uint32(uint16(size.X)) | uint32(uint16(size.Y))<<16)
}

func hresult(operation string, result uintptr) error {
	if int32(uint32(result)) < 0 {
		return fmt.Errorf("%s: HRESULT 0x%08x", operation, uint32(result))
	}
	return nil
}

func (l *Library) Create(size windows.Coord, input, output windows.Handle) (windows.Handle, error) {
	var console windows.Handle
	result, _, _ := l.create.Call(packedSize(size), uintptr(input), uintptr(output), 0, uintptr(unsafe.Pointer(&console)))
	return console, hresult("create pseudoconsole", result)
}

func (l *Library) Resize(console windows.Handle, size windows.Coord) error {
	result, _, _ := l.resize.Call(uintptr(console), packedSize(size))
	return hresult("resize pseudoconsole", result)
}

func (l *Library) Release(console windows.Handle) error {
	result, _, _ := l.release.Call(uintptr(console))
	return hresult("release pseudoconsole", result)
}

func (l *Library) CloseConsole(console windows.Handle) { _, _, _ = l.close.Call(uintptr(console)) }
