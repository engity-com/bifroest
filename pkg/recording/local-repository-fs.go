package recording

import (
	goerrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	localDirectoryMode = 0700
	localFileMode      = 0600
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
	if err := protectLocalHead(temporary, file); err != nil {
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
	file, err := openLocalHead(path)
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
