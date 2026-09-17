//go:build windows

package main

import (
	"errors"
	"fmt"
	goos "os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	fileAddFile     = 0x00000002
	fileDeleteChild = 0x00000040
)

func writeAuditOutputFile(path string, data []byte, force bool, validate func() error) error {
	return writeProtectedOutputFile(path, force, validate, func(output *goos.File) error {
		_, err := output.Write(data)
		return err
	})
}

func writeProtectedOutputFile(path string, force bool, validate func() error, produce func(*goos.File) error) (rErr error) {
	if produce == nil {
		return fmt.Errorf("nil output producer")
	}
	parentPath := filepath.Dir(path)
	parent, err := openAuditOutputParent(parentPath)
	if err != nil {
		return fmt.Errorf("cannot pin output parent directory: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(parent); err != nil && rErr == nil {
			rErr = err
		}
	}()
	if err := verifyAuditOutputParent(parent, parentPath); err != nil {
		return err
	}
	if validate != nil {
		if err := validate(); err != nil {
			return err
		}
	}
	if err := verifyAuditOutputParent(parent, parentPath); err != nil {
		return err
	}

	temporaryName, temporaryHandle, err := createAuditOutputTemporary(parent)
	if err != nil {
		return fmt.Errorf("cannot create private temporary output: %w", err)
	}
	temporary := goos.NewFile(uintptr(temporaryHandle), temporaryName)
	installed := false
	defer func() {
		if !installed {
			_ = deleteOpenWindowsFile(temporaryHandle)
		}
		if temporary != nil {
			if err := temporary.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
	}()
	if err := produce(temporary); err != nil {
		return fmt.Errorf("cannot produce private temporary output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("cannot flush private temporary output: %w", err)
	}
	if validate != nil {
		if err := validate(); err != nil {
			return err
		}
	}
	if err := verifyAuditOutputParent(parent, parentPath); err != nil {
		return err
	}
	if err := renameOpenWindowsFile(temporaryHandle, parent, filepath.Base(path), force); err != nil {
		return fmt.Errorf("cannot atomically install output: %w", err)
	}
	installed = true
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("cannot close installed output: %w", err)
	}
	temporary = nil
	if err := windows.FlushFileBuffers(parent); err != nil {
		return fmt.Errorf("cannot flush output parent directory: %w", err)
	}
	return nil
}

func openAuditOutputParent(path string) (windows.Handle, error) {
	volume := filepath.VolumeName(path)
	if volume == "" || !filepath.IsAbs(path) {
		return 0, fmt.Errorf("output parent %q is not an absolute drive or UNC path", path)
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return 0, err
	}
	components := []string(nil)
	if relative != "." {
		components = strings.Split(relative, string(filepath.Separator))
	}
	desiredAccess := uint32(windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	if len(components) == 0 {
		desiredAccess |= fileAddFile | fileDeleteChild
	}
	rootName, err := sys.WindowsPathPointer(root)
	if err != nil {
		return 0, err
	}
	current, err := windows.CreateFile(rootName, desiredAccess,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	if err := rejectWindowsReparsePoint(current); err != nil {
		_ = windows.CloseHandle(current)
		return 0, err
	}
	for index, component := range components {
		access := uint32(windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
		if index == len(components)-1 {
			access |= fileAddFile | fileDeleteChild
		}
		next, openErr := openWindowsPathRelative(current, component, access, windows.FILE_OPEN,
			windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, nil)
		closeErr := windows.CloseHandle(current)
		if openErr != nil {
			return 0, openErr
		}
		if closeErr != nil {
			_ = windows.CloseHandle(next)
			return 0, closeErr
		}
		if err := rejectWindowsReparsePoint(next); err != nil {
			_ = windows.CloseHandle(next)
			return 0, err
		}
		current = next
	}
	return current, nil
}

func openWindowsPathRelative(root windows.Handle, name string, access, disposition, options uint32, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	encoded, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}
	objectName := windows.NTUnicodeString{
		Length:        uint16((len(encoded) - 1) * 2),
		MaximumLength: uint16(len(encoded) * 2),
		Buffer:        &encoded[0],
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      root,
		ObjectName:         &objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options, 0, 0)
	runtime.KeepAlive(encoded)
	runtime.KeepAlive(descriptor)
	return handle, err
}

func rejectWindowsReparsePoint(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("output parent path contains a reparse point")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("output parent component is not a directory")
	}
	return nil
}

func verifyAuditOutputParent(parent windows.Handle, path string) (rErr error) {
	current, err := openAuditOutputParent(path)
	if err != nil {
		return fmt.Errorf("output parent changed after it was pinned: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(current); err != nil && rErr == nil {
			rErr = fmt.Errorf("cannot close current output parent: %w", err)
		}
	}()
	var pinnedInfo, currentInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(parent, &pinnedInfo); err != nil {
		return fmt.Errorf("cannot inspect pinned output parent: %w", err)
	}
	if err := windows.GetFileInformationByHandle(current, &currentInfo); err != nil {
		return fmt.Errorf("cannot inspect current output parent: %w", err)
	}
	if pinnedInfo.VolumeSerialNumber != currentInfo.VolumeSerialNumber ||
		pinnedInfo.FileIndexHigh != currentInfo.FileIndexHigh || pinnedInfo.FileIndexLow != currentInfo.FileIndexLow {
		return fmt.Errorf("output parent changed after it was pinned")
	}
	return nil
}

func createAuditOutputTemporary(parent windows.Handle) (string, windows.Handle, error) {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;OW)")
	if err != nil {
		return "", 0, err
	}
	for range 100 {
		name, err := randomAuditOutputTemporaryName()
		if err != nil {
			return "", 0, err
		}
		handle, err := openWindowsPathRelative(parent, name,
			windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
			windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, descriptor)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.NTStatus(0xc0000035)) {
			continue
		}
		if err != nil {
			return "", 0, err
		}
		return name, handle, nil
	}
	return "", 0, fmt.Errorf("cannot allocate a unique temporary output name")
}

type windowsFileRenameInformation struct {
	ReplaceIfExists byte
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

func renameOpenWindowsFile(file, parent windows.Handle, name string, force bool) error {
	encoded, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameBytes := (len(encoded) - 1) * 2
	headerSize := int(unsafe.Offsetof(windowsFileRenameInformation{}.FileName))
	buffer := make([]byte, headerSize+nameBytes)
	information := (*windowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	if force {
		information.ReplaceIfExists = 1
	}
	information.RootDirectory = parent
	information.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&information.FileName[0], len(encoded)-1), encoded[:len(encoded)-1])
	var status windows.IO_STATUS_BLOCK
	err = windows.NtSetInformationFile(file, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation)
	runtime.KeepAlive(encoded)
	return err
}

func deleteOpenWindowsFile(file windows.Handle) error {
	deleteFile := byte(1)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(file, &status, &deleteFile, 1, windows.FileDispositionInformation)
}
