//go:build windows

package environment

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// copyLocalWindowsProfileTemplate merges the contents of source into an
// already created profile directory. New entries are created as token's user
// and inherit the destination parent's ACL; template ACLs are not copied.
// A failed copy leaves previously created directories and even partially
// written files behind; they are never removed automatically because another
// process may have modified them. The caller must ensure the paths are not
// concurrently modified during copy.
func copyLocalWindowsProfileTemplate(source, target string, token windows.Token) error {
	if source == "" || target == "" {
		return fmt.Errorf("profile template and destination must not be empty")
	}
	src, err := filepath.Abs(source)
	if err != nil {
		return fmt.Errorf("resolve profile template: %w", err)
	}
	dst, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve profile destination: %w", err)
	}
	for _, pair := range [][2]string{{src, dst}, {dst, src}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (rel == "." || !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
			return fmt.Errorf("profile template and destination overlap: %q and %q", src, dst)
		}
	}
	if err := localProfileCheckAncestors(src); err != nil {
		return err
	}
	if err := localProfileCheckAncestors(dst); err != nil {
		return err
	}
	srcInfo, err := localProfileSafeInfo(src)
	if err != nil {
		return err
	}
	dstInfo, err := localProfileSafeInfo(dst)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() || !dstInfo.IsDir() || os.SameFile(srcInfo, dstInfo) {
		return fmt.Errorf("profile template and destination must be distinct directories")
	}
	for _, pair := range []struct {
		path  string
		other os.FileInfo
	}{{src, dstInfo}, {dst, srcInfo}} {
		for path := filepath.Dir(pair.path); ; path = filepath.Dir(path) {
			info, err := localProfileSafeInfo(path)
			if err != nil {
				return err
			}
			if os.SameFile(info, pair.other) {
				return fmt.Errorf("profile template and destination overlap: %q and %q", src, dst)
			}
			if filepath.Dir(path) == path {
				break
			}
		}
	}

	type entry struct {
		rel string
	}
	var directories, files []entry
	entries := make(map[string]bool)
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := localProfileSafeInfo(path)
		if err != nil {
			return err
		}
		if path == src {
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported profile template entry %q", path)
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("profile template entry escapes source: %q", path)
		}
		key := strings.ToLower(rel)
		if _, exists := entries[key]; exists {
			return fmt.Errorf("ambiguous profile template entry %q", path)
		}
		entries[key] = info.IsDir()
		if info.IsDir() {
			directories = append(directories, entry{rel})
		} else {
			files = append(files, entry{rel})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect profile template: %w", err)
	}
	// Inspect only names used by the template, without following unrelated
	// destination entries. Resolve names case-insensitively even in a directory
	// configured for case-sensitive lookups.
	children := make(map[string]map[string][]string)
	checkDestination := func(e entry, directory bool) error {
		parent := dst
		parts := strings.Split(e.rel, string(filepath.Separator))
		for i, part := range parts {
			names, ok := children[parent]
			if !ok {
				listed, err := os.ReadDir(parent)
				if err != nil {
					return fmt.Errorf("inspect profile destination %q: %w", parent, err)
				}
				names = make(map[string][]string, len(listed))
				for _, child := range listed {
					key := strings.ToLower(child.Name())
					names[key] = append(names[key], child.Name())
				}
				children[parent] = names
			}
			matches := names[strings.ToLower(part)]
			if len(matches) == 0 {
				return nil // This path and its descendants do not exist yet.
			}
			if len(matches) != 1 {
				return fmt.Errorf("ambiguous profile destination entry %q", filepath.Join(parent, part))
			}
			path := filepath.Join(parent, matches[0])
			info, err := localProfileSafeInfo(path)
			if err != nil {
				return err
			}
			if !info.IsDir() || (i == len(parts)-1 && !directory) {
				return fmt.Errorf("profile template collision at %q", path)
			}
			parent = path
		}
		return nil
	}
	for _, e := range directories {
		if err := checkDestination(e, true); err != nil {
			return fmt.Errorf("inspect profile destination: %w", err)
		}
	}
	for _, e := range files {
		if err := checkDestination(e, false); err != nil {
			return fmt.Errorf("inspect profile destination: %w", err)
		}
	}

	// The caller stays under its original identity to open each source file;
	// only the destination worker ever adopts the target user's token.
	type openedSource struct {
		file *os.File
		err  error
	}
	requests := make(chan string)
	opened := make(chan openedSource)
	done := make(chan error, 1)
	go func() {
		done <- func() (result error) {
			runtime.LockOSThread()
			var impersonation windows.Token
			if err := windows.DuplicateTokenEx(token, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
				runtime.UnlockOSThread()
				return fmt.Errorf("duplicate profile user token: %w", err)
			}
			defer impersonation.Close()
			if err := windows.SetThreadToken(nil, impersonation); err != nil {
				runtime.UnlockOSThread()
				return fmt.Errorf("impersonate profile user: %w", err)
			}
			defer func() {
				if err := windows.RevertToSelf(); err != nil {
					result = errors.Join(result, fmt.Errorf("revert profile user impersonation: %w", err))
					return // Never return a still-impersonated thread to the Go scheduler.
				}
				runtime.UnlockOSThread()
			}()
			if _, err := os.ReadDir(dst); err != nil {
				return fmt.Errorf("access profile destination %q as user: %w", dst, err)
			}
			for _, e := range directories {
				path := filepath.Join(dst, e.rel)
				if err := localProfileCheckAncestors(filepath.Dir(path)); err != nil {
					return err
				}
				info, err := localProfileSafeInfo(path)
				if errors.Is(err, os.ErrNotExist) {
					if err := os.Mkdir(path, 0777); err != nil {
						return fmt.Errorf("create profile directory %q: %w", path, err)
					}
					info, err = localProfileSafeInfo(path)
				}
				if err != nil {
					return err
				}
				if !info.IsDir() {
					return fmt.Errorf("profile directory collision at %q", path)
				}
				if _, err := os.ReadDir(path); err != nil {
					return fmt.Errorf("access profile directory %q as user: %w", path, err)
				}
			}
			for _, e := range files {
				to := filepath.Join(dst, e.rel)
				if err := localProfileCheckAncestors(filepath.Dir(to)); err != nil {
					return err
				}
				if _, err := localProfileSafeInfo(to); err == nil {
					return fmt.Errorf("profile template collision at %q", to)
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				requests <- e.rel
				source := <-opened
				if source.err != nil {
					return source.err
				}
				output, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
				if err != nil {
					source.file.Close()
					return fmt.Errorf("create profile file %q: %w", to, err)
				}
				_, copyErr := io.Copy(output, source.file)
				closeErr := output.Close()
				inputErr := source.file.Close()
				if err := errors.Join(copyErr, closeErr, inputErr); err != nil {
					return fmt.Errorf("copy profile file %q: %w", to, err)
				}
				check, err := os.Open(to)
				if err != nil {
					return fmt.Errorf("reopen profile file %q as user: %w", to, err)
				}
				if err := check.Close(); err != nil {
					return fmt.Errorf("close reopened profile file %q: %w", to, err)
				}
			}
			return nil
		}()
	}()
	for {
		select {
		case rel := <-requests:
			from := filepath.Join(src, rel)
			var source openedSource
			if source.err = localProfileCheckAncestors(filepath.Dir(from)); source.err == nil {
				var name *uint16
				name, source.err = syscall.UTF16PtrFromString(from)
				if source.err == nil {
					var h syscall.Handle
					h, source.err = syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
					if source.err == nil {
						source.file = os.NewFile(uintptr(h), from)
						var info syscall.ByHandleFileInformation
						source.err = syscall.GetFileInformationByHandle(h, &info)
						if source.err == nil && info.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
							source.err = fmt.Errorf("unsafe profile template file %q", from)
						}
					}
				}
			}
			if source.err != nil {
				if source.file != nil {
					source.file.Close()
				}
				source.err = fmt.Errorf("open profile template file %q: %w", from, source.err)
			}
			opened <- source
		case err := <-done:
			return err
		}
	}
}

func localProfileCheckAncestors(path string) error {
	for {
		if _, err := localProfileSafeInfo(path); err != nil {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func localProfileSafeInfo(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect profile path %q: %w", path, err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	attrs, err := syscall.GetFileAttributes(name)
	if err != nil {
		return nil, fmt.Errorf("inspect profile attributes %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("reparse point in profile path %q", path)
	}
	return info, nil
}
