package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

const nativeHeadFileName = "head.cbor"

// Remove only temps that are an exact prefix of a signed head for the
// checkpoint or the fully verified chain tip. No file is unlinked until the
// chain and every candidate (including its inode and aliases) are checked.
func discardNativeHeadTemps(directory string, identity *Identity, checkpoint, tip journalHash, temps map[string]struct{}, segments []nativeSegmentEntry, activePath string) error {
	if len(temps) == 0 {
		return nil
	}
	_, oldPayload, err := newNativeAuditHead(identity, checkpoint)
	if err != nil {
		return err
	}
	_, tipPayload, err := newNativeAuditHead(identity, tip)
	if err != nil {
		return err
	}
	paths := []string{filepath.Join(directory, nativeHeadFileName), filepath.Join(filepath.Dir(directory), journalLockFileName)}
	for _, segment := range segments {
		paths = append(paths, segment.path)
	}
	if _, err := os.Lstat(activePath); err == nil {
		paths = append(paths, activePath)
	} else if !os.IsNotExist(err) {
		return err
	}
	type candidate struct {
		path string
		info os.FileInfo
		data []byte
	}
	var candidates []candidate
	for name := range temps {
		path := filepath.Join(directory, name)
		f, err := nativeOpenRegular(path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		if info.Size() < 0 || info.Size() > nativeformat.MaxMetadataPayload {
			_ = f.Close()
			return fmt.Errorf("invalid native head temp size %q", name)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, nativeformat.MaxMetadataPayload+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return firstNativeError(readErr, closeErr)
		}
		if !bytes.HasPrefix(oldPayload, data) && !bytes.HasPrefix(tipPayload, data) {
			return fmt.Errorf("native head temp %q is not part of the verified chain", name)
		}
		for _, other := range paths {
			otherInfo, err := os.Lstat(other)
			if err != nil {
				return err
			}
			if os.SameFile(info, otherInfo) {
				return fmt.Errorf("native head temp %q aliases repository data", name)
			}
		}
		for _, other := range candidates {
			if os.SameFile(info, other.info) {
				return fmt.Errorf("native head temps alias each other")
			}
		}
		candidates = append(candidates, candidate{path, info, data})
	}
	for _, item := range candidates {
		current, err := os.Lstat(item.path)
		if err != nil {
			return err
		}
		if !current.Mode().IsRegular() || !os.SameFile(item.info, current) || current.Size() != item.info.Size() {
			return fmt.Errorf("native head temp changed: %s", item.path)
		}
		f, err := nativeOpenRegular(item.path)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, nativeformat.MaxMetadataPayload+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return firstNativeError(readErr, closeErr)
		}
		if !bytes.Equal(data, item.data) {
			return fmt.Errorf("native head temp changed: %s", item.path)
		}
		if err := os.Remove(item.path); err != nil {
			return err
		}
		if err := syncJournalDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func readNativeHead(directory string, identity *Identity) (journalHash, error) {
	path := filepath.Join(directory, nativeHeadFileName)
	f, err := nativeOpenRegular(path)
	if err != nil {
		return journalHash{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, nativeformat.MaxMetadataPayload+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return journalHash{}, fmt.Errorf("read native head: %w", firstNativeError(readErr, closeErr))
	}
	h, err := decodeNativeAuditHead(data, identity)
	if err != nil {
		return journalHash{}, err
	}
	return journalHash(h.LastRecordHash), nil
}

func writeNativeHead(directory string, identity *Identity, expected *journalHash, hash journalHash) error {
	target := filepath.Join(directory, nativeHeadFileName)
	checkTarget := func() error {
		if expected == nil {
			_, err := os.Lstat(target)
			if err == nil {
				return fmt.Errorf("native audit head already exists")
			}
			if !os.IsNotExist(err) {
				return err
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				return err
			}
			if len(entries) != 0 {
				return fmt.Errorf("native audit head missing with existing entries")
			}
			return nil
		}
		current, err := readNativeHead(directory, identity)
		if err != nil {
			return err
		}
		if current != *expected {
			return fmt.Errorf("native audit head changed before update")
		}
		return nil
	}
	if err := checkTarget(); err != nil {
		return err
	}
	_, payload, err := newNativeAuditHead(identity, hash)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(directory, ".head-cbor-*")
	if err != nil {
		return err
	}
	path := f.Name()
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		_ = f.Close()
		if current, err := os.Lstat(path); err == nil && os.SameFile(info, current) {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(journalFileMode); err != nil {
		return err
	}
	if n, err := f.Write(payload); err != nil {
		return err
	} else if n != len(payload) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if expected != nil {
		if err := checkTarget(); err != nil {
			return err
		}
	} else {
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			return fmt.Errorf("native audit head appeared before publication: %v", err)
		}
	}
	if err := replaceJournalFile(path, target); err != nil {
		return err
	}
	return syncJournalDirectory(directory)
}

func firstNativeError(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
