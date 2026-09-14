package recording

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	localRecordingDirectoryMode = 0700
	localRecordingFileMode      = 0600
)

func canonicalLocalRecordingDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("local recording directory is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if canonical, err := filepath.EvalSymlinks(absolute); err == nil {
		return canonical, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if info, err := os.Lstat(absolute); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("local recording directory is a dangling symlink")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, localRecordingDirectoryMode); err != nil {
		return "", err
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(canonicalParent, filepath.Base(absolute)), nil
}

func ensureLocalRecordingDirectory(path string) error {
	if err := os.Mkdir(path, localRecordingDirectoryMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local recording path is not a regular directory")
	}
	if err := secureLocalRecordingDirectory(path, info); err != nil {
		return err
	}
	if err := syncLocalRecordingDirectory(path); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(filepath.Dir(path))
}

func createLocalRecordingFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, localRecordingFileMode)
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openActiveLocalRecordingFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("active local recording is not a regular file")
	}
	if err := makeActiveLocalRecordingWritable(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, localRecordingFileMode)
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenLocalRecordingFile(path string, file *os.File) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("local recording path changed while opening the file")
	}
	return nil
}

func writeLocalRecordingHead(directory string, value []byte) error {
	temporary := filepath.Join(directory, localRecordingHeadTempFileName)
	target := filepath.Join(directory, localRecordingHeadFileName)
	file, err := createLocalRecordingFile(temporary)
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
	if err := protectLocalRecordingHead(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceLocalRecordingFile(temporary, target); err != nil {
		return err
	}
	removeTemporary = false
	return syncLocalRecordingDirectory(directory)
}

func loadLocalRecordingHead(path string) ([]byte, error) {
	file, err := openLocalRecordingHead(path)
	if err != nil {
		return nil, err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maximumCastZstdHeadBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(payload) > maximumCastZstdHeadBytes {
		return nil, errors.New("local recording head exceeds its size limit")
	}
	return payload, nil
}

func discardLocalRecordingHeadTemporary(directory string) error {
	path := filepath.Join(directory, localRecordingHeadTempFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("temporary local recording head is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(directory)
}

func prepareInterruptedLocalRecordingHead(directory string) error {
	head := filepath.Join(directory, localRecordingHeadFileName)
	temporary := filepath.Join(directory, localRecordingHeadTempFileName)
	if info, err := os.Lstat(head); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("local recording head is not a regular file")
		}
		return discardLocalRecordingHeadTemporary(directory)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if info, err := os.Lstat(temporary); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("local recording head is missing")
		}
		return err
	} else if !info.Mode().IsRegular() {
		return errors.New("temporary local recording head is not a regular file")
	}
	payload, err := loadLocalRecordingHead(temporary)
	if err != nil {
		return err
	}
	if _, err := decodeCastZstdHead(payload); err != nil {
		return err
	}
	if err := replaceLocalRecordingFile(temporary, head); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(directory)
}
