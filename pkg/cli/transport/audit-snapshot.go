package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

const WireAuditCommand = wire.WireAuditCommand
const MaxAuditSnapshotBytes = wire.MaxAuditSnapshotBytes
const maxAuditSnapshotFileBytes = wire.MaxAuditSnapshotFileBytes

type AuditSnapshotEntry = wire.AuditSnapshotEntry
type AuditSnapshotHeader = wire.AuditSnapshotHeader

type AuditSnapshot struct {
	header AuditSnapshotHeader
	root   string
}

func (this *AuditSnapshot) Close() error {
	if this == nil || this.root == "" {
		return nil
	}
	root := this.root
	this.root = ""
	return os.RemoveAll(root)
}

func permittedAuditSnapshotName(name string, encrypted bool) bool {
	return wire.PermittedAuditSnapshotName(name, encrypted)
}

// SnapshotAudit copies a live signed checkpoint into private temporary storage.
// A concurrent append/rotation is retried; no partially verified snapshot is
// ever returned to the SSH transport.
func SnapshotAudit(ctx context.Context, source audit.JournalSource) (*AuditSnapshot, error) {
	if source.Name == "" || source.Directory == "" || source.ExpectedProducerId.IsZero() {
		return nil, fmt.Errorf("audit snapshot requires name, directory and trusted producer")
	}
	source.WithSensitive = false
	source.DecryptionIdentities = nil
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := audit.VerifyLiveJournalIntegrity(ctx, []audit.JournalSource{source}); err != nil {
			lastErr = err
			continue
		}
		root, err := os.MkdirTemp("", "bifroest-management-audit-*")
		if err != nil {
			return nil, err
		}
		snapshot := &AuditSnapshot{root: root, header: AuditSnapshotHeader{
			Version: 1, Name: source.Name, Producer: source.ExpectedProducerId.String(), Recipient: source.ExpectedEncryptionRecipient,
		}}
		if err = snapshot.copy(ctx, source); err == nil {
			err = audit.VerifyJournalIntegrity(ctx, []audit.JournalSource{{
				Name: source.Name, Directory: snapshot.Directory(), ExpectedProducerId: source.ExpectedProducerId,
				ExpectedEncryptionRecipient: source.ExpectedEncryptionRecipient,
			}})
		}
		if err == nil {
			return snapshot, nil
		}
		lastErr = err
		_ = snapshot.Close()
	}
	return nil, fmt.Errorf("cannot capture a stable signed audit checkpoint: %w", lastErr)
}

func (this *AuditSnapshot) Directory() string { return filepath.Join(this.root, "journal") }

func (this *AuditSnapshot) copy(ctx context.Context, source audit.JournalSource) error {
	producer := source.ExpectedProducerId.String()
	input := filepath.Join(source.Directory, producer)
	output := filepath.Join(this.Directory(), producer)
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(input)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !permittedAuditSnapshotName(name, source.ExpectedEncryptionRecipient != "") || !entry.Type().IsRegular() {
			return fmt.Errorf("invalid signed audit snapshot entry %q", name)
		}
		path := filepath.Join(input, name)
		initial, err := os.Lstat(path)
		if err != nil || !initial.Mode().IsRegular() || initial.Size() > maxAuditSnapshotFileBytes || initial.Size() < 1 {
			return fmt.Errorf("invalid audit source file %q: %v", path, err)
		}
		if total > MaxAuditSnapshotBytes-initial.Size() {
			return fmt.Errorf("audit snapshot exceeds %d bytes", MaxAuditSnapshotBytes)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(initial, opened) {
			_ = file.Close()
			return fmt.Errorf("audit file %q changed while opening: %v", path, err)
		}
		data, err := io.ReadAll(io.LimitReader(file, maxAuditSnapshotFileBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || int64(len(data)) != initial.Size() {
			return fmt.Errorf("audit file %q changed while copying: %v", path, errors.Join(err, closeErr))
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(initial, current) || current.Size() != initial.Size() || !current.ModTime().Equal(initial.ModTime()) {
			return fmt.Errorf("audit file %q changed during snapshot: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		this.header.Files = append(this.header.Files, AuditSnapshotEntry{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
		total += int64(len(data))
	}
	return nil
}

func (this *AuditSnapshot) StreamTo(output io.Writer) error {
	if this == nil || this.root == "" || output == nil {
		return fmt.Errorf("closed audit snapshot or missing output")
	}
	if err := wire.WriteAuditSnapshotHeader(output, this.header); err != nil {
		return err
	}
	producerDir := filepath.Join(this.Directory(), this.header.Producer)
	for _, entry := range this.header.Files {
		file, err := os.Open(filepath.Join(producerDir, entry.Name))
		if err != nil {
			return err
		}
		written, err := io.CopyN(output, file, entry.Size)
		closeErr := file.Close()
		if err != nil || closeErr != nil || written != entry.Size {
			return errors.Join(err, closeErr, io.ErrUnexpectedEOF)
		}
	}
	return nil
}

func ReadAuditSnapshot(input io.Reader, root string) (AuditSnapshotHeader, error) {
	return wire.ReadAuditSnapshot(input, &auditSnapshotFileSink{root: root})
}

// The native caller supplies private staging storage and owns its cleanup. A
// successfully decoded transfer still needs successful SSH exit and independent
// journal verification before its files can be treated as trusted evidence.
type auditSnapshotFileSink struct{ root, directory string }

func (this *auditSnapshotFileSink) Begin(header AuditSnapshotHeader) error {
	this.directory = filepath.Join(this.root, "journal", header.Producer)
	return os.MkdirAll(this.directory, 0700)
}
func (this *auditSnapshotFileSink) Open(entry AuditSnapshotEntry) (io.WriteCloser, error) {
	return os.OpenFile(filepath.Join(this.directory, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
