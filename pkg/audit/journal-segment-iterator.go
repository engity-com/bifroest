package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	goerrors "errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalDirectoryReadBatch   = 128
	journalSegmentSortChunkSize = 1_024
	journalSegmentRunRecordSize = 8 + sha256.Size + 1
)

type sortedJournalSegmentIterator struct {
	directory string
	memory    []journalSegmentFile
	index     int
	run       *os.File
	runPath   string
	workspace *journalSegmentWorkspace
}

type journalSegmentSorter struct {
	directory     string
	tempDirectory string
	chunk         []journalSegmentFile
	runs          []string
	pendingRun    string
	finishRun     string
	finishLevel   int
	cleanupPaths  []string
	workspace     *journalSegmentWorkspace
	newWorkspace  func() (*journalSegmentWorkspace, error)
}

func newSortedJournalSegmentIterator(ctx context.Context, directory, tempDirectory string, classify func(os.DirEntry) (*journalSegmentFile, error)) (*sortedJournalSegmentIterator, error) {
	if tempDirectory == "" {
		return nil, errors.System.Newf("private audit segment workspace is empty")
	}
	return buildSortedJournalSegmentIterator(ctx, directory, tempDirectory, nil, classify)
}

func newSortedJournalSegmentIteratorWithWorkspace(ctx context.Context, directory string, workspace func() (*journalSegmentWorkspace, error), classify func(os.DirEntry) (*journalSegmentFile, error)) (*sortedJournalSegmentIterator, error) {
	return buildSortedJournalSegmentIterator(ctx, directory, "", workspace, classify)
}

func buildSortedJournalSegmentIterator(ctx context.Context, directory, tempDirectory string, workspace func() (*journalSegmentWorkspace, error), classify func(os.DirEntry) (*journalSegmentFile, error)) (*sortedJournalSegmentIterator, error) {
	sorter := &journalSegmentSorter{
		directory:     directory,
		tempDirectory: tempDirectory,
		chunk:         make([]journalSegmentFile, 0, journalSegmentSortChunkSize),
		newWorkspace:  workspace,
	}
	err := forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		segment, err := classify(entry)
		if err != nil || segment == nil {
			return err
		}
		return sorter.add(ctx, *segment)
	})
	if err != nil {
		return nil, goerrors.Join(err, sorter.cleanup())
	}
	iterator, err := sorter.finish(ctx)
	if err != nil {
		return nil, goerrors.Join(err, sorter.cleanup())
	}
	iterator.workspace = sorter.workspace
	return iterator, nil
}

func forEachJournalDirectoryEntry(ctx context.Context, directory string, consumer func(os.DirEntry) error) error {
	file, err := os.Open(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit directory %q: %w", directory, err)
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return errors.System.Newf("audit directory iteration canceled: %w", err)
		}
		entries, readErr := file.ReadDir(journalDirectoryReadBatch)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				_ = file.Close()
				return errors.System.Newf("audit directory iteration canceled: %w", err)
			}
			if err := consumer(entry); err != nil {
				_ = file.Close()
				return err
			}
		}
		if readErr == io.EOF {
			if err := file.Close(); err != nil {
				return errors.System.Newf("cannot close audit directory %q: %w", directory, err)
			}
			return nil
		}
		if readErr != nil {
			_ = file.Close()
			return errors.System.Newf("cannot inspect audit directory %q: %w", directory, readErr)
		}
	}
}

func journalDirectoryHasEntry(ctx context.Context, directory string, include func(os.DirEntry) bool) (bool, error) {
	found := false
	stop := goerrors.New("audit directory entry found")
	err := forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		if include(entry) {
			found = true
			return stop
		}
		return nil
	})
	if goerrors.Is(err, stop) {
		return true, nil
	}
	return found, err
}

func (this *journalSegmentSorter) add(ctx context.Context, segment journalSegmentFile) error {
	this.chunk = append(this.chunk, segment)
	if len(this.chunk) < journalSegmentSortChunkSize {
		return nil
	}
	return this.flush(ctx)
}

func (this *journalSegmentSorter) flush(ctx context.Context) error {
	if len(this.chunk) == 0 {
		return nil
	}
	if this.newWorkspace != nil && this.workspace == nil {
		workspace, err := this.newWorkspace()
		if err != nil {
			return err
		}
		this.workspace = workspace
		this.tempDirectory = workspace.path
	}
	sort.Slice(this.chunk, func(left, right int) bool {
		return journalSegmentLess(this.chunk[left], this.chunk[right])
	})
	path, err := writeJournalSegmentRun(ctx, this.tempDirectory, this.chunk)
	if err != nil {
		return err
	}
	this.chunk = this.chunk[:0]
	this.pendingRun = path
	return this.resumePendingRun(ctx)
}

func (this *journalSegmentSorter) resume(ctx context.Context) error {
	if err := this.resumePendingRun(ctx); err != nil {
		return err
	}
	if len(this.chunk) >= journalSegmentSortChunkSize {
		return this.flush(ctx)
	}
	return nil
}

func (this *journalSegmentSorter) resumePendingRun(ctx context.Context) error {
	carry := this.pendingRun
	if carry == "" {
		return nil
	}
	for level := 0; ; level++ {
		if level == len(this.runs) {
			this.runs = append(this.runs, carry)
			this.pendingRun = ""
			return nil
		}
		if this.runs[level] == "" {
			this.runs[level] = carry
			this.pendingRun = ""
			return nil
		}
		left := this.runs[level]
		merged, err := mergeJournalSegmentRuns(ctx, this.tempDirectory, left, carry)
		if err != nil {
			return err
		}
		if err := goerrors.Join(removeJournalSegmentRun(left), removeJournalSegmentRun(carry)); err != nil {
			this.cleanupPaths = append(this.cleanupPaths, left, carry, merged)
			return goerrors.Join(err, removeJournalSegmentRun(merged))
		}
		this.runs[level] = ""
		carry = merged
		this.pendingRun = merged
	}
}

func (this *journalSegmentSorter) finish(ctx context.Context) (*sortedJournalSegmentIterator, error) {
	if len(this.runs) == 0 && this.pendingRun == "" {
		sort.Slice(this.chunk, func(left, right int) bool {
			return journalSegmentLess(this.chunk[left], this.chunk[right])
		})
		return &sortedJournalSegmentIterator{directory: this.directory, memory: this.chunk}, nil
	}
	if err := this.resumePendingRun(ctx); err != nil {
		return nil, err
	}
	if err := this.flush(ctx); err != nil {
		return nil, err
	}
	for this.finishLevel < len(this.runs) {
		path := this.runs[this.finishLevel]
		if path == "" {
			this.finishLevel++
			continue
		}
		if this.finishRun == "" {
			this.finishRun = path
			this.runs[this.finishLevel] = ""
			this.finishLevel++
			continue
		}
		merged, err := mergeJournalSegmentRuns(ctx, this.tempDirectory, this.finishRun, path)
		if err != nil {
			return nil, err
		}
		if err := goerrors.Join(removeJournalSegmentRun(this.finishRun), removeJournalSegmentRun(path)); err != nil {
			this.cleanupPaths = append(this.cleanupPaths, this.finishRun, path, merged)
			return nil, goerrors.Join(err, removeJournalSegmentRun(merged))
		}
		this.runs[this.finishLevel] = ""
		this.finishRun = merged
		this.finishLevel++
	}
	file, err := os.Open(this.finishRun)
	if err != nil {
		return nil, errors.System.Newf("cannot open sorted audit segment run: %w", err)
	}
	final := this.finishRun
	this.finishRun = ""
	return &sortedJournalSegmentIterator{directory: this.directory, run: file, runPath: final}, nil
}

func (this *journalSegmentSorter) cleanup() error {
	var result error
	for index, path := range this.runs {
		if path != "" {
			result = goerrors.Join(result, removeJournalSegmentRun(path))
			this.runs[index] = ""
		}
	}
	result = goerrors.Join(result, removeJournalSegmentRun(this.pendingRun), removeJournalSegmentRun(this.finishRun))
	this.pendingRun = ""
	this.finishRun = ""
	for _, path := range this.cleanupPaths {
		result = goerrors.Join(result, removeJournalSegmentRun(path))
	}
	this.cleanupPaths = nil
	result = goerrors.Join(result, this.workspace.Close())
	this.workspace = nil
	return result
}

func (this *sortedJournalSegmentIterator) Next(ctx context.Context) (journalSegmentFile, bool, error) {
	if err := ctx.Err(); err != nil {
		return journalSegmentFile{}, false, errors.System.Newf("audit segment iteration canceled: %w", err)
	}
	if this.run == nil {
		if this.index >= len(this.memory) {
			return journalSegmentFile{}, false, nil
		}
		segment := this.memory[this.index]
		this.index++
		return segment, true, nil
	}
	segment, found, err := readJournalSegmentRunRecord(this.run, this.directory)
	if err != nil {
		return journalSegmentFile{}, false, errors.System.Newf("cannot read sorted audit segment run: %w", err)
	}
	return segment, found, nil
}

func (this *sortedJournalSegmentIterator) Reset() error {
	if this.run == nil {
		this.index = 0
		return nil
	}
	if _, err := this.run.Seek(0, io.SeekStart); err != nil {
		return errors.System.Newf("cannot reset sorted audit segment run: %w", err)
	}
	return nil
}

func (this *sortedJournalSegmentIterator) Close() error {
	if this == nil {
		return nil
	}
	var result error
	if this.run != nil {
		result = this.run.Close()
		this.run = nil
	}
	if this.runPath != "" {
		result = goerrors.Join(result, removeJournalSegmentRun(this.runPath))
		this.runPath = ""
	}
	result = goerrors.Join(result, this.workspace.Close())
	this.workspace = nil
	return result
}

func writeJournalSegmentRun(ctx context.Context, tempDirectory string, segments []journalSegmentFile) (string, error) {
	file, err := bfcrypto.CreateProtectedTempFile(tempDirectory, ".bifroest-audit-segments-*", 0600)
	if err != nil {
		return "", errors.System.Newf("cannot create temporary audit segment run: %w", err)
	}
	path := file.Name()
	for _, segment := range segments {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return "", goerrors.Join(errors.System.Newf("audit segment sorting canceled: %w", err), removeJournalSegmentRun(path))
		}
		if err := writeJournalSegmentRunRecord(file, segment); err != nil {
			_ = file.Close()
			return "", goerrors.Join(errors.System.Newf("cannot write temporary audit segment run: %w", err), removeJournalSegmentRun(path))
		}
	}
	if err := file.Close(); err != nil {
		return "", goerrors.Join(errors.System.Newf("cannot close temporary audit segment run: %w", err), removeJournalSegmentRun(path))
	}
	return path, nil
}

func mergeJournalSegmentRuns(ctx context.Context, tempDirectory, leftPath, rightPath string) (string, error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return "", errors.System.Newf("cannot open temporary audit segment run: %w", err)
	}
	right, err := os.Open(rightPath)
	if err != nil {
		_ = left.Close()
		return "", errors.System.Newf("cannot open temporary audit segment run: %w", err)
	}
	output, err := bfcrypto.CreateProtectedTempFile(tempDirectory, ".bifroest-audit-segments-*", 0600)
	if err != nil {
		_ = left.Close()
		_ = right.Close()
		return "", errors.System.Newf("cannot create merged audit segment run: %w", err)
	}
	outputPath := output.Name()
	fail := func(cause error) (string, error) {
		return "", goerrors.Join(cause, left.Close(), right.Close(), output.Close(), removeJournalSegmentRun(outputPath))
	}
	leftSegment, leftFound, err := readJournalSegmentRunRecord(left, "")
	if err != nil {
		return fail(err)
	}
	rightSegment, rightFound, err := readJournalSegmentRunRecord(right, "")
	if err != nil {
		return fail(err)
	}
	for leftFound || rightFound {
		if err := ctx.Err(); err != nil {
			return fail(errors.System.Newf("audit segment sorting canceled: %w", err))
		}
		useLeft := leftFound && (!rightFound || journalSegmentLess(leftSegment, rightSegment))
		segment := rightSegment
		if useLeft {
			segment = leftSegment
		}
		if err := writeJournalSegmentRunRecord(output, segment); err != nil {
			return fail(errors.System.Newf("cannot merge temporary audit segment runs: %w", err))
		}
		if useLeft {
			leftSegment, leftFound, err = readJournalSegmentRunRecord(left, "")
		} else {
			rightSegment, rightFound, err = readJournalSegmentRunRecord(right, "")
		}
		if err != nil {
			return fail(err)
		}
	}
	if err := goerrors.Join(left.Close(), right.Close(), output.Close()); err != nil {
		return "", goerrors.Join(errors.System.Newf("cannot close temporary audit segment runs: %w", err), removeJournalSegmentRun(outputPath))
	}
	return outputPath, nil
}

func journalSegmentLess(left, right journalSegmentFile) bool {
	if left.sequence != right.sequence {
		return left.sequence < right.sequence
	}
	return bytes.Compare(left.hash[:], right.hash[:]) < 0
}

func writeJournalSegmentRunRecord(writer io.Writer, segment journalSegmentFile) error {
	var raw [journalSegmentRunRecordSize]byte
	binary.BigEndian.PutUint64(raw[:8], segment.sequence)
	copy(raw[8:], segment.hash[:])
	switch {
	case strings.HasSuffix(segment.name, ".baudit"):
		raw[len(raw)-1] = 1
	case strings.HasSuffix(segment.name, ".beaudit"):
		raw[len(raw)-1] = 2
	case segment.name == "" || strings.HasSuffix(segment.name, ".journal"):
	default:
		return errors.System.Newf("unsupported temporary audit segment name %q", segment.name)
	}
	written, err := writer.Write(raw[:])
	if err == nil && written != len(raw) {
		err = io.ErrShortWrite
	}
	return err
}

func readJournalSegmentRunRecord(reader io.Reader, directory string) (journalSegmentFile, bool, error) {
	var raw [journalSegmentRunRecordSize]byte
	_, err := io.ReadFull(reader, raw[:])
	if err == io.EOF {
		return journalSegmentFile{}, false, nil
	}
	if err != nil {
		return journalSegmentFile{}, false, err
	}
	sequence := binary.BigEndian.Uint64(raw[:8])
	if sequence == 0 {
		return journalSegmentFile{}, false, errors.System.Newf("temporary audit segment run contains sequence zero")
	}
	var hash journalHash
	copy(hash[:], raw[8:8+sha256.Size])
	var name string
	switch raw[len(raw)-1] {
	case 0:
		name = sealedJournalFileName(sequence, hash)
	case 1:
		name = nativeSegmentName(sequence, hash, false)
	case 2:
		name = nativeSegmentName(sequence, hash, true)
	default:
		return journalSegmentFile{}, false, errors.System.Newf("temporary audit segment run contains invalid mode")
	}
	return journalSegmentFile{name: name, path: filepath.Join(directory, name), sequence: sequence, hash: hash}, true, nil
}

func removeJournalSegmentRun(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !goerrors.Is(err, os.ErrNotExist) {
		return errors.System.Newf("cannot remove temporary audit segment run %q: %w", path, err)
	}
	return nil
}
