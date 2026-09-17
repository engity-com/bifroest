package recording

import (
	stderrors "errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sync"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localQuota struct {
	mutex   sync.Mutex
	maximum uint64
	usage   uint64
}

func newLocalQuota(maximum uint64, paths ...string) (*localQuota, error) {
	if maximum < 1 {
		return nil, errors.Config.Newf("maximum local recording spool bytes must be positive")
	}
	usage, recoveredUsage, err := inventoryLocalFilesWithReceiptRecovery(paths...)
	if err != nil {
		return nil, errors.System.Newf("cannot inventory local recording spool: %w", err)
	}
	if usage > maximum && recoveredUsage > maximum {
		return nil, errors.Config.Newf("local recording spool uses %d bytes, exceeding its %d-byte limit", usage, maximum)
	}
	return &localQuota{maximum: maximum, usage: usage}, nil
}

func inventoryLocalFiles(paths ...string) (uint64, error) {
	total, _, err := inventoryLocalFilesWithReceiptRecovery(paths...)
	return total, err
}

func inventoryLocalFilesWithReceiptRecovery(paths ...string) (uint64, uint64, error) {
	var total uint64
	var replacedReceiptBytes uint64
	var seen []os.FileInfo
	for _, root := range paths {
		if _, err := os.Lstat(root); stderrors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return 0, 0, err
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			for _, previous := range seen {
				if os.SameFile(previous, info) {
					return nil
				}
			}
			if info.Size() < 0 {
				return errors.System.Newf("local recording file has a negative size")
			}
			size := uint64(info.Size())
			if total > math.MaxUint64-size {
				return errors.System.Newf("local recording spool size overflows uint64")
			}
			seen = append(seen, info)
			total += size
			if filepath.Base(root) == localDeliveryDirectory && entry.Name() == "receipt.tmp" {
				target, targetErr := os.Lstat(filepath.Join(filepath.Dir(path), "receipt.json"))
				if targetErr == nil && target.Mode().IsRegular() && target.Size() >= 0 {
					targetSize := uint64(target.Size())
					if replacedReceiptBytes > math.MaxUint64-targetSize {
						return errors.System.Newf("local recording receipt recovery size overflows uint64")
					}
					replacedReceiptBytes += targetSize
				} else if targetErr != nil && !stderrors.Is(targetErr, fs.ErrNotExist) {
					return targetErr
				}
			}
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	}
	if replacedReceiptBytes > total {
		return 0, 0, errors.System.Newf("local recording receipt recovery size exceeds spool usage")
	}
	return total, total - replacedReceiptBytes, nil
}

func (this *localQuota) reserve(bytes uint64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.usage > this.maximum || bytes > this.maximum-this.usage {
		return errors.System.Newf("local recording spool limit of %d bytes would be exceeded", this.maximum)
	}
	this.usage += bytes
	return nil
}

func (this *localQuota) Reserve(bytes uint64) error {
	return this.reserve(bytes)
}

func (this *localQuota) release(bytes uint64) error {
	if this == nil || bytes <= 0 {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if bytes > this.usage {
		return errors.System.Newf("local recording spool accounting underflow")
	}
	this.usage -= bytes
	return nil
}

func (this *localQuota) reconcile(reserved uint64, before, after int64) error {
	if before < 0 || after < 0 {
		return errors.System.Newf("local recording file has a negative size")
	}
	if after < before {
		return this.release(reserved + uint64(before-after))
	}
	growth := uint64(after - before)
	if growth <= reserved {
		return this.release(reserved - growth)
	}
	if err := this.reserve(growth - reserved); err != nil {
		return errors.System.Newf("local recording file grew beyond its reservation: %w", err)
	}
	return nil
}

func (this *localQuota) Reconcile(reserved uint64, before, after int64) error {
	return this.reconcile(reserved, before, after)
}

type localQuotaFile struct {
	*os.File
	quota *localQuota
	mutex sync.Mutex
}

func accountLocalFile(file *os.File, quota *localQuota) *localQuotaFile {
	return &localQuotaFile{File: file, quota: quota}
}

func (this *localQuotaFile) Write(value []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	before, err := this.Stat()
	if err != nil {
		return 0, err
	}
	offset, err := this.Seek(0, 1)
	if err != nil {
		return 0, err
	}
	if offset < 0 || int64(len(value)) > math.MaxInt64-offset {
		return 0, errors.System.Newf("local recording write size overflows int64")
	}
	reserved := uint64(max(int64(0), offset+int64(len(value))-before.Size()))
	if err := this.quota.reserve(reserved); err != nil {
		return 0, err
	}
	written, writeErr := this.File.Write(value)
	after, statErr := this.Stat()
	if statErr != nil {
		return written, stderrors.Join(writeErr, statErr)
	}
	reconcileErr := this.quota.reconcile(reserved, before.Size(), after.Size())
	return written, stderrors.Join(writeErr, reconcileErr)
}

func (this *localQuotaFile) Truncate(size int64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if size < 0 {
		return errors.System.Newf("cannot truncate a local recording to a negative size")
	}
	before, err := this.Stat()
	if err != nil {
		return err
	}
	reserved := uint64(max(int64(0), size-before.Size()))
	if err := this.quota.reserve(reserved); err != nil {
		return err
	}
	truncateErr := this.File.Truncate(size)
	after, statErr := this.Stat()
	if statErr != nil {
		return stderrors.Join(truncateErr, statErr)
	}
	return stderrors.Join(truncateErr, this.quota.reconcile(reserved, before.Size(), after.Size()))
}

func removeAccountedLocalFile(path string, quota *localQuota) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		return quota.release(uint64(info.Size()))
	}
	return nil
}

func removeAccountedLocalTree(path string, quota *localQuota) error {
	usage, inventoryErr := inventoryLocalFiles(path)
	removeErr := os.RemoveAll(path)
	if removeErr == nil && inventoryErr == nil {
		return quota.release(usage)
	}
	return stderrors.Join(inventoryErr, removeErr)
}
