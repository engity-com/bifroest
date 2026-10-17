package recording

import (
	"bytes"
	"container/heap"
	"context"
	stderrors "errors"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	DefaultSealedPageSize uint = 100
	MaximumSealedPageSize uint = 1000
)

type SealedPageOptions struct {
	After Id
	Limit uint
}

func (this SealedPageOptions) Validate() error {
	if this.Limit < 1 || this.Limit > MaximumSealedPageSize {
		return errors.Config.Newf("recording list limit must be between 1 and %d", MaximumSealedPageSize)
	}
	if !this.After.IsZero() {
		return validateId(this.After)
	}
	return nil
}

type SealedRecordingFile struct {
	ID   Id
	Name string
}

// ReadSealedRecordingPage selects canonical native filenames in ascending ID
// order without reading artifact contents. Callers must verify the selected
// artifacts before exposing their metadata. Inventory memory is bounded by the
// page size plus a fixed directory batch, regardless of the directory's size.
func ReadSealedRecordingPage(ctx context.Context, path string, options SealedPageOptions) (result []SealedRecordingFile, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = stderrors.Join(resultErr, directory.Close()) }()
	return readSealedRecordingPage(ctx, directory, []string{".bcast", ".becast"}, options)
}

type sealedDirectoryReader interface {
	ReadDir(int) ([]os.DirEntry, error)
}

func readSealedRecordingPage(ctx context.Context, directory sealedDirectoryReader, suffixes []string, options SealedPageOptions) ([]SealedRecordingFile, error) {
	// One look-ahead entry detects an ambiguous ID at the page boundary.
	capacity := int(options.Limit) + 1
	selected := make(sealedPageFiles, 0, capacity)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			file, skipped, err := sealedPageFile(entry, suffixes)
			if err != nil {
				return nil, err
			}
			if skipped || bytes.Compare(file.ID[:], options.After[:]) <= 0 {
				continue
			}
			if len(selected) < capacity {
				heap.Push(&selected, file)
			} else if compareSealedPageFiles(file, selected[0]) < 0 {
				selected[0] = file
				heap.Fix(&selected, 0)
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return nil, readErr
			}
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(selected, func(i, j int) bool { return compareSealedPageFiles(selected[i], selected[j]) < 0 })
	for i := 1; i < len(selected); i++ {
		if selected[i-1].ID == selected[i].ID {
			return nil, errors.Config.Newf("recording %s has ambiguous sealed artifacts", selected[i].ID)
		}
	}
	if len(selected) > int(options.Limit) {
		selected = selected[:options.Limit]
	}
	return selected, nil
}

func sealedPageFile(entry os.DirEntry, suffixes []string) (SealedRecordingFile, bool, error) {
	for _, suffix := range suffixes {
		if strings.HasSuffix(entry.Name(), suffix+localRetentionTombstone) {
			_, skipped, err := localRetentionTombstoneId(entry.Name(), suffix)
			return SealedRecordingFile{}, skipped, err
		}
		if strings.HasSuffix(entry.Name(), suffix) {
			id, err := localSealedEntryId(entry, suffix)
			return SealedRecordingFile{ID: id, Name: entry.Name()}, false, err
		}
	}
	return SealedRecordingFile{}, false, errors.Config.Newf("sealed recording directory contains unsupported entry %q", entry.Name())
}

type sealedPageFiles []SealedRecordingFile

func (this sealedPageFiles) Len() int           { return len(this) }
func (this sealedPageFiles) Less(i, j int) bool { return compareSealedPageFiles(this[i], this[j]) > 0 }
func (this sealedPageFiles) Swap(i, j int)      { this[i], this[j] = this[j], this[i] }
func (this *sealedPageFiles) Push(value any)    { *this = append(*this, value.(SealedRecordingFile)) }
func (this *sealedPageFiles) Pop() any {
	last := len(*this) - 1
	result := (*this)[last]
	(*this)[last] = SealedRecordingFile{}
	*this = (*this)[:last]
	return result
}

func compareSealedPageFiles(left, right SealedRecordingFile) int {
	if compared := bytes.Compare(left.ID[:], right.ID[:]); compared != 0 {
		return compared
	}
	return strings.Compare(left.Name, right.Name)
}

func (this *localRepository[Head, Summary]) listSealedPage(ctx context.Context, options SealedPageOptions) (result []Id, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resultErr = this.withSealedDirectory(ctx, func(directory *os.File) error {
		files, err := readSealedRecordingPage(ctx, directory, []string{this.format.sealedSuffix()}, options)
		if err != nil {
			return err
		}
		result = make([]Id, 0, len(files))
		for _, file := range files {
			result = append(result, file.ID)
		}
		return nil
	})
	return result, resultErr
}

// Only opening the directory holds the repository mutex. The operation remains
// registered for shutdown while the potentially large inventory is scanned.
func (this *localRepository[Head, Summary]) withSealedDirectory(ctx context.Context, consume func(*os.File) error) (resultErr error) {
	if this == nil {
		return errors.System.Newf("nil local recording repository")
	}
	if err := this.mutex.LockContext(ctx); err != nil {
		return err
	}
	if this.closed {
		this.mutex.Unlock()
		return errors.System.Newf("local recording repository is closed")
	}
	if this.poisoned != nil {
		err := this.poisoned
		this.mutex.Unlock()
		return err
	}
	if err := validateLocalLock(this.processLock, this.lockPath); err != nil {
		this.mutex.Unlock()
		return err
	}
	directory, err := os.Open(this.sealedPath)
	if err != nil {
		this.mutex.Unlock()
		return err
	}
	this.operations.Add(1)
	this.mutex.Unlock()
	defer this.operations.Done()
	defer func() { resultErr = stderrors.Join(resultErr, directory.Close()) }()
	return consume(directory)
}
