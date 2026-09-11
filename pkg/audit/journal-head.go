package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalHeadFileName        = "head.json"
	journalHeadTempFileName    = "head.tmp"
	journalHeadSchema          = "bifroest.audit-journal-head/v1"
	journalHeadSignatureDomain = "BIFROEST-AUDIT-JOURNAL-HEAD-SIGNATURE/v1\x00"
)

type journalHeadContent struct {
	Schema         string      `json:"schema"`
	ProducerId     ProducerId  `json:"producerId"`
	LastRecordHash journalHash `json:"lastRecordHash"`
	PublicKey      []byte      `json:"publicKey"`
}

type journalHead struct {
	journalHeadContent
	Signature []byte `json:"signature"`
}

func newJournalHead(identity *Identity, lastRecordHash journalHash) (journalHead, []byte, error) {
	content := journalHeadContent{
		Schema:         journalHeadSchema,
		ProducerId:     identity.ProducerId(),
		LastRecordHash: lastRecordHash,
		PublicKey:      identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalHead{}, nil, errors.System.Newf("cannot encode audit journal head: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalHeadSignatureDomain), unsigned...))
	if err != nil {
		return journalHead{}, nil, err
	}
	head := journalHead{journalHeadContent: content, Signature: signature}
	payload, err := json.Marshal(head)
	if err != nil {
		return journalHead{}, nil, errors.System.Newf("cannot encode signed audit journal head: %w", err)
	}
	return head, payload, nil
}

func decodeJournalHead(payload []byte, identity journalIdentity) (journalHead, error) {
	var head journalHead
	if err := decodeCanonicalJournalPayload(payload, &head); err != nil {
		return journalHead{}, err
	}
	if head.Schema != journalHeadSchema || head.ProducerId != identity.ProducerId() || !bytes.Equal(head.PublicKey, identity.journalPublicKey()) {
		return journalHead{}, errors.Config.Newf("audit journal head belongs to a different identity")
	}
	unsigned, err := json.Marshal(head.journalHeadContent)
	if err != nil {
		return journalHead{}, errors.System.Newf("cannot re-encode audit journal head: %w", err)
	}
	if err := identity.verify(append([]byte(journalHeadSignatureDomain), unsigned...), head.Signature); err != nil {
		return journalHead{}, err
	}
	return head, nil
}

func loadOrCreateJournalHead(directory string, identity *Identity) (journalHead, error) {
	if err := discardInterruptedJournalHead(directory); err != nil {
		return journalHead{}, err
	}
	path := filepath.Join(directory, journalHeadFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		entries, readErr := os.ReadDir(directory)
		if readErr != nil {
			return journalHead{}, errors.System.Newf("cannot inspect audit producer directory %q: %w", directory, readErr)
		}
		if len(entries) != 0 {
			return journalHead{}, errors.Config.Newf("audit journal head is missing while producer directory %q contains history", directory)
		}
		head, _, createErr := newJournalHead(identity, journalHash{})
		if createErr != nil {
			return journalHead{}, createErr
		}
		if createErr := writeJournalHead(directory, identity, head.LastRecordHash); createErr != nil {
			return journalHead{}, createErr
		}
		return head, nil
	}
	if err != nil {
		return journalHead{}, errors.System.Newf("cannot inspect audit journal head %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return journalHead{}, errors.Config.Newf("audit journal head %q is not a regular file", path)
	}
	file, err := openJournalHead(path)
	if err != nil {
		return journalHead{}, err
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxJournalRecordPayloadSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return journalHead{}, errors.System.Newf("cannot read audit journal head %q: %w", path, readErr)
	}
	if closeErr != nil {
		return journalHead{}, errors.System.Newf("cannot close audit journal head %q: %w", path, closeErr)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return journalHead{}, errors.System.Newf("audit journal head exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	return decodeJournalHead(payload, identity)
}

func writeJournalHead(directory string, identity *Identity, lastRecordHash journalHash) error {
	_, payload, err := newJournalHead(identity, lastRecordHash)
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, journalHeadTempFileName)
	target := filepath.Join(directory, journalHeadFileName)
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return errors.System.Newf("cannot create temporary audit journal head %q: %w", temporary, err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	written, err := file.Write(payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = file.Close()
		return errors.System.Newf("cannot write audit journal head: %w", err)
	}
	if err := protectJournalHead(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return errors.System.Newf("cannot close audit journal head: %w", err)
	}
	if err := replaceJournalFile(temporary, target); err != nil {
		return errors.System.Newf("cannot publish audit journal head: %w", err)
	}
	removeTemporary = false
	if err := syncJournalDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush audit journal head: %w", err)
	}
	return nil
}

func discardInterruptedJournalHead(directory string) error {
	path := filepath.Join(directory, journalHeadTempFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.System.Newf("cannot inspect temporary audit journal head %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("temporary audit journal head %q is not a regular file", path)
	}
	if err := os.Remove(path); err != nil {
		return errors.System.Newf("cannot discard temporary audit journal head %q: %w", path, err)
	}
	return syncJournalDirectory(directory)
}
