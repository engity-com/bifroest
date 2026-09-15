package recording

import (
	"bytes"
	goerrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	localDirectoryMode      = 0700
	localFileMode           = 0600
	maximumLocalFormatBytes = 64
)

func canonicalLocalDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.Config.Newf("local recording directory is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if canonical, err := filepath.EvalSymlinks(absolute); err == nil {
		return canonical, nil
	} else if !goerrors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Config.Newf("local recording directory is a dangling symlink")
	} else if err != nil && !goerrors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, localDirectoryMode); err != nil {
		return "", err
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(canonicalParent, filepath.Base(absolute)), nil
}

func ensureLocalDirectory(path string) error {
	if err := os.Mkdir(path, localDirectoryMode); err != nil && !goerrors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Config.Newf("local recording path is not a regular directory")
	}
	if err := secureLocalDirectory(path, info); err != nil {
		return err
	}
	if err := syncLocalDirectory(path); err != nil {
		return err
	}
	return syncLocalDirectory(filepath.Dir(path))
}

func createLocalFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, localFileMode)
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openActiveLocalFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.Config.Newf("active local recording is not a regular file")
	}
	if err := makeActiveLocalWritable(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func removeLocalFileIfSame(path string, expected os.FileInfo) error {
	file, err := openReadOnlyLocalFile(path)
	if goerrors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return goerrors.Join(err, file.Close())
	}
	if expected == nil || !os.SameFile(expected, info) {
		return goerrors.Join(errors.System.Newf("local recording file changed before cleanup"), file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if goerrors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return errors.System.Newf("local recording file changed before cleanup")
	}
	return os.Remove(path)
}

func validateOpenLocalFile(path string, file *os.File) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.System.Newf("local recording path changed while opening the file")
	}
	return nil
}

func writeLocalHead(directory string, value []byte) error {
	temporary := filepath.Join(directory, localHeadTempFileName)
	target := filepath.Join(directory, localHeadFileName)
	file, err := createLocalFile(temporary)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	written, err := file.Write(value)
	if err == nil && written != len(value) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = file.Close()
		return err
	}
	if err := protectLocalReadOnlyFile(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceLocalFile(temporary, target); err != nil {
		return err
	}
	removeTemporary = false
	return syncLocalDirectory(directory)
}

func loadLocalHead(path string, maximumBytes int64) ([]byte, error) {
	if maximumBytes < 1 {
		return nil, errors.Config.Newf("local recording head size limit must be positive")
	}
	file, err := openProtectedLocalFile(path)
	if err != nil {
		return nil, err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(payload)) > maximumBytes {
		return nil, errors.Config.Newf("local recording head exceeds its size limit")
	}
	return payload, nil
}

func bindLocalFormat(directory, key string) error {
	expected := []byte(key + "\n")
	if !isCanonicalLocalFormatPayload(expected) {
		return errors.Config.Newf("local recording format key is invalid")
	}
	temporary := filepath.Join(directory, localFormatTempFileName)
	target := filepath.Join(directory, localFormatFileName)
	if _, err := completeLocalPublishAlias(temporary, target); err != nil {
		return errors.System.Newf("cannot complete local format publication: %w", err)
	}

	if _, err := os.Lstat(target); err == nil {
		if _, temporaryErr := os.Lstat(temporary); temporaryErr == nil {
			return errors.Config.Newf("local recording format marker conflicts with its temporary file")
		} else if !goerrors.Is(temporaryErr, fs.ErrNotExist) {
			return temporaryErr
		}
		return validateLocalFormatFile(target, expected)
	} else if !goerrors.Is(err, fs.ErrNotExist) {
		return err
	}

	if _, err := os.Lstat(temporary); goerrors.Is(err, fs.ErrNotExist) {
		if err := validateUnboundLocalRoot(directory); err != nil {
			return err
		}
		if err := writeProtectedLocalFile(temporary, expected); err != nil {
			return errors.System.Newf("cannot write local recording format marker: %w", err)
		}
	} else if err != nil {
		return err
	} else {
		if err := validateUnboundLocalRootWithTemporary(directory); err != nil {
			return err
		}
		ready, err := prepareLocalFormatTemporary(directory, temporary, expected)
		if err != nil {
			return err
		}
		if !ready {
			return bindLocalFormat(directory, key)
		}
	}
	if err := publishLocalFile(temporary, target); err != nil {
		return errors.System.Newf("cannot publish local recording format marker: %w", err)
	}
	return validateLocalFormatFile(target, expected)
}

func writeProtectedLocalFile(path string, value []byte) error {
	file, err := createLocalFile(path)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		closeErr := file.Close()
		return goerrors.Join(err, closeErr)
	}
	cleanup := func(cause error) error {
		closeErr := file.Close()
		removeErr := removeLocalFileIfSame(path, info)
		return goerrors.Join(cause, closeErr, removeErr)
	}
	written, writeErr := file.Write(value)
	if writeErr == nil && written != len(value) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return cleanup(writeErr)
	}
	if err := protectLocalReadOnlyFile(path, file); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		return goerrors.Join(err, removeLocalFileIfSame(path, info))
	}
	return nil
}

func validateUnboundLocalRoot(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != localLockFileName {
			return errors.Config.Newf("markerless local recording repository is not empty")
		}
	}
	return nil
}

func prepareLocalFormatTemporary(directory, path string, expected []byte) (bool, error) {
	file, mutableErr := openMutablePrivateLocalFile(path)
	if mutableErr != nil {
		if err := validateLocalFormatFile(path, expected); err != nil {
			return false, err
		}
		return true, nil
	}
	info, err := file.Stat()
	if err != nil {
		return false, goerrors.Join(err, file.Close())
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximumLocalFormatBytes+1))
	if readErr != nil {
		return false, goerrors.Join(readErr, file.Close())
	}
	if bytes.Equal(payload, expected) {
		protectErr := protectLocalReadOnlyFile(path, file)
		closeErr := file.Close()
		return protectErr == nil && closeErr == nil, goerrors.Join(protectErr, closeErr)
	}
	if isCanonicalLocalFormatPayload(payload) {
		return false, goerrors.Join(errors.Config.Newf("local recording repository uses a different format"), file.Close())
	}
	if err := validateUnboundLocalRootWithTemporary(directory); err != nil {
		return false, goerrors.Join(err, file.Close())
	}
	closeErr := file.Close()
	if closeErr != nil {
		return false, closeErr
	}
	if err := removeLocalFileIfSame(path, info); err != nil {
		return false, err
	}
	if err := syncLocalDirectory(directory); err != nil {
		return false, err
	}
	return false, nil
}

func validateUnboundLocalRootWithTemporary(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != localLockFileName && entry.Name() != localFormatTempFileName {
			return errors.Config.Newf("local recording repository has state alongside a malformed format temporary")
		}
	}
	return nil
}

func isCanonicalLocalFormatPayload(payload []byte) bool {
	if len(payload) < 5 || len(payload) > maximumLocalFormatBytes || payload[len(payload)-1] != '\n' {
		return false
	}
	key := payload[:len(payload)-1]
	slash := bytes.IndexByte(key, '/')
	if slash < 1 || slash != bytes.LastIndexByte(key, '/') || slash+2 >= len(key) || key[slash+1] != 'v' || key[slash+2] < '1' || key[slash+2] > '9' {
		return false
	}
	for _, current := range key[:slash] {
		if current != '-' && (current < 'a' || current > 'z') && (current < '0' || current > '9') {
			return false
		}
	}
	for _, current := range key[slash+2:] {
		if current < '0' || current > '9' {
			return false
		}
	}
	return true
}

func validateLocalFormatFile(path string, expected []byte) error {
	file, err := openProtectedLocalFile(path)
	if err != nil {
		return err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximumLocalFormatBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(payload) > maximumLocalFormatBytes || !bytes.Equal(payload, expected) {
		return errors.Config.Newf("local recording repository uses a different or malformed format")
	}
	return nil
}

func discardLocalHeadTemporary(directory string) error {
	path := filepath.Join(directory, localHeadTempFileName)
	info, err := os.Lstat(path)
	if goerrors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("temporary local recording head is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncLocalDirectory(directory)
}

func prepareInterruptedLocalHead(directory string, maximumBytes int64, validate func([]byte) error) error {
	if validate == nil {
		return errors.Config.Newf("nil local recording head validator")
	}
	head := filepath.Join(directory, localHeadFileName)
	temporary := filepath.Join(directory, localHeadTempFileName)
	if info, err := os.Lstat(head); err == nil {
		if !info.Mode().IsRegular() {
			return errors.Config.Newf("local recording head is not a regular file")
		}
		payload, err := loadLocalHead(head, maximumBytes)
		if err != nil {
			return err
		}
		if err := validate(payload); err != nil {
			return err
		}
		return discardLocalHeadTemporary(directory)
	} else if !goerrors.Is(err, fs.ErrNotExist) {
		return err
	}
	if info, err := os.Lstat(temporary); err != nil {
		if goerrors.Is(err, fs.ErrNotExist) {
			return errors.Config.Newf("local recording head is missing")
		}
		return err
	} else if !info.Mode().IsRegular() {
		return errors.Config.Newf("temporary local recording head is not a regular file")
	}
	payload, err := loadLocalHead(temporary, maximumBytes)
	if err != nil {
		return err
	}
	if err := validate(payload); err != nil {
		return err
	}
	if err := replaceLocalFile(temporary, head); err != nil {
		return err
	}
	return syncLocalDirectory(directory)
}
