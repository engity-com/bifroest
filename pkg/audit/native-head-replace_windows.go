//go:build windows

package audit

import (
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	fileRenameReplaceIfExists = 0x01
	fileRenamePosixSemantics  = 0x02
)

// MoveFileEx(REPLACE_EXISTING) refuses an open target even with FILE_SHARE_DELETE.
// FileRenameInfoEx atomically replaces the name while existing verifier handles
// continue to read the old signed head. Unsupported filesystems fail closed.
func replaceNativeHeadFile(source, target string) (resultErr error) {
	if filepath.Clean(filepath.Dir(source)) != filepath.Clean(filepath.Dir(target)) {
		return fmt.Errorf("native audit head replacement must remain in the same directory")
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("invalid native audit head temporary file: %v", err)
	}
	from, err := sys.WindowsPathPointer(source)
	if err != nil {
		return err
	}
	to, err := sys.WindowsExtendedPath(target)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(to)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(from, windows.GENERIC_WRITE|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), source)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("cannot wrap native audit head temporary file handle")
	}
	defer func() { resultErr = goerrors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return fmt.Errorf("native audit head temporary file changed: %v", err)
	}
	// Layout of FILE_RENAME_INFO: flags, pointer-sized RootDirectory,
	// FileNameLength (bytes), followed by a variable-length UTF-16 name.
	var layout struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	nameOffset := int(unsafe.Offsetof(layout.FileName))
	buffer := make([]byte, nameOffset+len(name)*2)
	binary.LittleEndian.PutUint32(buffer, fileRenameReplaceIfExists|fileRenamePosixSemantics)
	binary.LittleEndian.PutUint32(buffer[unsafe.Offsetof(layout.FileNameLength):], uint32((len(name)-1)*2))
	for index, code := range name {
		binary.LittleEndian.PutUint16(buffer[nameOffset+index*2:], code)
	}
	if err := windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer))); err != nil {
		return fmt.Errorf("cannot atomically replace native audit head: %w", err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("cannot flush replaced native audit head: %w", err)
	}
	return nil
}
