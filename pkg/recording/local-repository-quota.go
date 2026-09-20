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
	return newLocalQuotaWithReceiptRecovery(maximum, false, paths...)
}

func newLocalQuotaWithReceiptRecovery(maximum uint64, allowReceiptRecovery bool, paths ...string) (*localQuota, error) {
	if maximum < 1 {
		return nil, errors.Config.Newf("maximum local recording spool bytes must be positive")
	}
	usage, recoveredUsage, err := inventoryLocalFilesWithReceiptRecovery(paths...)
	if err != nil {
		return nil, errors.System.Newf("cannot inventory local recording spool: %w", err)
	}
	if usage > maximum && (!allowReceiptRecovery || recoveredUsage > maximum) {
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
	seen := make(map[localInventoryFileIdentity]struct{})
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
			identity, err := inventoryLocalFileIdentity(path, info)
			if err != nil {
				return err
			}
			if _, exists := seen[identity]; exists {
				return nil
			}
			if info.Size() < 0 {
				return errors.System.Newf("local recording file has a negative size")
			}
			size := uint64(info.Size())
			if total > math.MaxUint64-size {
				return errors.System.Newf("local recording spool size overflows uint64")
			}
			seen[identity] = struct{}{}
			total += size
			var replacedReceipt string
			if filepath.Base(root) == localDeliveryDirectory {
				switch entry.Name() {
				case "receipt.tmp":
					replacedReceipt = "receipt.json"
				case "receipt.retention.tmp":
					replacedReceipt = "receipt.retention"
				}
			}
			if replacedReceipt != "" {
				target, targetErr := os.Lstat(filepath.Join(filepath.Dir(path), replacedReceipt))
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
	quota     *localQuota
	mutex     sync.Mutex
	reserved  uint64
	uncertain bool
}

func accountLocalFile(file *os.File, quota *localQuota) *localQuotaFile {
	return &localQuotaFile{File: file, quota: quota}
}

func (this *localQuotaFile) adoptReservedBytes(bytes uint64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.uncertain {
		return errors.System.Newf("local recording quota usage is uncertain")
	}
	if bytes > math.MaxUint64-this.reserved {
		return errors.System.Newf("local recording recovery reservation overflows uint64")
	}
	this.reserved += bytes
	return nil
}

func (this *localQuotaFile) releaseReservedBytes() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.uncertain {
		return errors.System.Newf("local recording quota usage is uncertain")
	}
	if err := this.quota.release(this.reserved); err != nil {
		return err
	}
	this.reserved = 0
	return nil
}

func (this *localQuotaFile) reserveGrowth(growth uint64) (uint64, error) {
	if this.uncertain {
		return 0, errors.System.Newf("local recording quota usage is uncertain")
	}
	reserved := min(growth, this.reserved)
	quotaBytes := growth - reserved
	if err := this.quota.reserve(quotaBytes); err != nil {
		return 0, err
	}
	return quotaBytes, nil
}

func (this *localQuotaFile) reconcileGrowth(quotaBytes uint64, before, after int64) error {
	if before < 0 || after < 0 {
		return errors.System.Newf("local recording file has a negative size")
	}
	if after < before {
		return this.quota.release(quotaBytes + uint64(before-after))
	}
	growth := uint64(after - before)
	reserved := min(growth, this.reserved)
	this.reserved -= reserved
	quotaGrowth := growth - reserved
	if quotaGrowth <= quotaBytes {
		return this.quota.release(quotaBytes - quotaGrowth)
	}
	if err := this.quota.reserve(quotaGrowth - quotaBytes); err != nil {
		return errors.System.Newf("local recording file grew beyond its reservation: %w", err)
	}
	return nil
}

func (this *localQuotaFile) Write(value []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	before, err := this.Stat()
	if err != nil {
		return 0, err
	}
	offset, err := this.File.Seek(0, 1)
	if err != nil {
		return 0, err
	}
	if offset < 0 || int64(len(value)) > math.MaxInt64-offset {
		return 0, errors.System.Newf("local recording write size overflows int64")
	}
	growth := uint64(max(int64(0), offset+int64(len(value))-before.Size()))
	quotaBytes, err := this.reserveGrowth(growth)
	if err != nil {
		return 0, err
	}
	written, writeErr := this.File.Write(value)
	after, statErr := this.Stat()
	if statErr != nil {
		this.uncertain = true
		return written, stderrors.Join(writeErr, statErr)
	}
	reconcileErr := this.reconcileGrowth(quotaBytes, before.Size(), after.Size())
	if reconcileErr != nil {
		this.uncertain = true
	}
	return written, stderrors.Join(writeErr, reconcileErr)
}

func (this *localQuotaFile) Seek(offset int64, whence int) (int64, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.File.Seek(offset, whence)
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
	growth := uint64(max(int64(0), size-before.Size()))
	quotaBytes, err := this.reserveGrowth(growth)
	if err != nil {
		return err
	}
	truncateErr := this.File.Truncate(size)
	after, statErr := this.Stat()
	if statErr != nil {
		this.uncertain = true
		return stderrors.Join(truncateErr, statErr)
	}
	reconcileErr := this.reconcileGrowth(quotaBytes, before.Size(), after.Size())
	if reconcileErr != nil {
		this.uncertain = true
	}
	return stderrors.Join(truncateErr, reconcileErr)
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
