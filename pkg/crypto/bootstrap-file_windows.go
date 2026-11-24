//go:build windows

package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func installBootstrapFile(temporary, target string, force bool) error {
	if force {
		return replaceBootstrapFile(temporary, target)
	}
	from, err := windowsPathPointer(temporary)
	if err != nil {
		return err
	}
	to, err := windowsPathPointer(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

// MoveFileEx(REPLACE_EXISTING) cannot replace a target held open by a reader.
// FileRenameInfoEx with POSIX semantics publishes the protected temporary file
// atomically while readers retain the old generation. Unsupported filesystems
// fail closed instead of falling back to unlinking or rewriting the live file.
func replaceBootstrapFile(temporary, target string) (resultErr error) {
	if filepath.Clean(filepath.Dir(temporary)) != filepath.Clean(filepath.Dir(target)) {
		return fmt.Errorf("bootstrap file replacement must remain in the same directory")
	}
	info, err := os.Lstat(temporary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("bootstrap temporary file must be a regular file")
	}
	from, err := windowsPathPointer(temporary)
	if err != nil {
		return err
	}
	to, err := windowsExtendedPath(target)
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
	file := os.NewFile(uintptr(handle), temporary)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("cannot wrap bootstrap temporary file handle")
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("bootstrap temporary file changed while opening")
	}
	// FILE_RENAME_INFO contains pointer-sized padding before the UTF-16 name.
	var layout struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	const (
		fileRenameReplaceIfExists = 0x01
		fileRenamePosixSemantics  = 0x02
	)
	nameOffset := int(unsafe.Offsetof(layout.FileName))
	buffer := make([]byte, nameOffset+len(name)*2)
	binary.LittleEndian.PutUint32(buffer, fileRenameReplaceIfExists|fileRenamePosixSemantics)
	binary.LittleEndian.PutUint32(buffer[unsafe.Offsetof(layout.FileNameLength):], uint32((len(name)-1)*2))
	for index, code := range name {
		binary.LittleEndian.PutUint16(buffer[nameOffset+index*2:], code)
	}
	if err := windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer))); err != nil {
		return fmt.Errorf("cannot atomically replace bootstrap file: %w", err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("cannot flush replaced bootstrap file: %w", err)
	}
	return nil
}
