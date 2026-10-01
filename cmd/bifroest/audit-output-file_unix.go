//go:build unix

package main

import (
	"fmt"
	goos "os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
		if err := parent.Close(); err != nil && rErr == nil {
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

	temporaryName, temporary, err := createAuditOutputTemporary(parent)
	if err != nil {
		return fmt.Errorf("cannot create private temporary output: %w", err)
	}
	installed := false
	defer func() {
		if temporary != nil {
			if err := temporary.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
		if !installed {
			_ = unix.Unlinkat(int(parent.Fd()), temporaryName, 0)
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
	if err := installAuditOutputFile(int(parent.Fd()), temporaryName, filepath.Base(path), force); err != nil {
		return err
	}
	installed = true
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("cannot close installed output: %w", err)
	}
	temporary = nil
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("cannot flush output parent directory: %w", err)
	}
	return nil
}

func openAuditOutputParent(path string) (*goos.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("output parent %q is not absolute", path)
	}
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeErr := unix.Close(current)
		if openErr != nil {
			return nil, openErr
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return nil, closeErr
		}
		current = next
	}
	return goos.NewFile(uintptr(current), path), nil
}

func verifyAuditOutputParent(parent *goos.File, path string) error {
	pinned, err := parent.Stat()
	if err != nil {
		return fmt.Errorf("cannot inspect pinned output parent: %w", err)
	}
	current, err := goos.Stat(path)
	if err != nil {
		return fmt.Errorf("output parent changed after it was pinned: %w", err)
	}
	if !goos.SameFile(pinned, current) {
		return fmt.Errorf("output parent changed after it was pinned")
	}
	return nil
}

func createAuditOutputTemporary(parent *goos.File) (string, *goos.File, error) {
	for range 100 {
		name, err := randomAuditOutputTemporaryName()
		if err != nil {
			return "", nil, err
		}
		handle, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, goos.NewFile(uintptr(handle), name), nil
	}
	return "", nil, fmt.Errorf("cannot allocate a unique temporary output name")
}
