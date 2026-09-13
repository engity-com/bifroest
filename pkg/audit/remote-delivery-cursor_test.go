package audit

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestRemoteDeliveryCursorIsCanonicalSignedAndScoped(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	hash := SegmentHash(hashJournalBytes(journalSegmentHashDomain, []byte("segment")))
	fingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("destination")))
	cursor, payload, err := newRemoteDeliveryCursor(identity, "archive", fingerprint, 42, hash)
	require.NoError(t, err)

	decoded, err := decodeRemoteDeliveryCursor(payload, identity, "archive", fingerprint)
	require.NoError(t, err)
	require.Equal(t, cursor, decoded)
	require.Equal(t, uint64(42), decoded.Sequence)
	require.Equal(t, hash, decoded.SegmentHash)

	_, err = decodeRemoteDeliveryCursor(payload, identity, "other", fingerprint)
	require.ErrorContains(t, err, "different producer or target")

	var tampered remoteDeliveryCursor
	require.NoError(t, json.Unmarshal(payload, &tampered))
	tampered.Sequence++
	tamperedPayload, err := json.Marshal(tampered)
	require.NoError(t, err)
	_, err = decodeRemoteDeliveryCursor(tamperedPayload, identity, "archive", fingerprint)
	require.ErrorContains(t, err, "illegal audit signature")

	otherFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("other-destination")))
	_, err = decodeRemoteDeliveryCursor(payload, identity, "archive", otherFingerprint)
	require.ErrorContains(t, err, "different destination")
	tampered.DestinationFingerprint = otherFingerprint
	tampered.Sequence = cursor.Sequence
	tamperedPayload, err = json.Marshal(tampered)
	require.NoError(t, err)
	_, err = decodeRemoteDeliveryCursor(tamperedPayload, identity, "archive", otherFingerprint)
	require.ErrorContains(t, err, "illegal audit signature")

	stateDirectory, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	targetDirectory := filepath.Join(stateDirectory, remoteDeliveryTargetStateName(configuration.AuditlogTargetName("archive")))
	_, err = loadRemoteDeliveryCursor(stateDirectory, identity, "archive", fingerprint)
	require.NoError(t, err)
	written, err := writeRemoteDeliveryCursor(targetDirectory, identity, "archive", fingerprint, 42, hash)
	require.NoError(t, err)
	loaded, err := loadRemoteDeliveryCursor(stateDirectory, identity, "archive", fingerprint)
	require.NoError(t, err)
	require.Equal(t, written, loaded)
}

func TestRemoteDeliveryTargetStateNamesAvoidFilesystemAliases(t *testing.T) {
	lower := remoteDeliveryTargetStateName("archive")
	upper := remoteDeliveryTargetStateName("ARCHIVE")
	require.NotEqual(t, lower, upper)
	require.Len(t, lower, 64)
	require.True(t, isRemoteDeliveryTargetStateName(lower))
	require.False(t, isRemoteDeliveryTargetStateName("CON"))
	require.False(t, isRemoteDeliveryTargetStateName("."+lower))
}

func TestRemoteDeliveryRecoversCompleteTemporaryCursor(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	fingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("destination")))
	stateDirectory, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(stateDirectory, identity, "archive", fingerprint)
	require.NoError(t, err)
	targetDirectory := filepath.Join(stateDirectory, remoteDeliveryTargetStateName("archive"))

	firstHash := SegmentHash(hashJournalBytes(journalSegmentHashDomain, []byte("first")))
	_, err = writeRemoteDeliveryCursor(targetDirectory, identity, "archive", fingerprint, 1, firstHash)
	require.NoError(t, err)
	secondHash := SegmentHash(hashJournalBytes(journalSegmentHashDomain, []byte("second")))
	second, payload, err := newRemoteDeliveryCursor(identity, "archive", fingerprint, 2, secondHash)
	require.NoError(t, err)
	temporary := filepath.Join(targetDirectory, remoteDeliveryCursorTempFileName)
	require.NoError(t, writeRemoteDeliveryTestFile(temporary, payload))

	loaded, err := loadRemoteDeliveryCursor(stateDirectory, identity, "archive", fingerprint)
	require.NoError(t, err)
	require.Equal(t, second, loaded)
	require.NoFileExists(t, temporary)

	require.NoError(t, writeRemoteDeliveryTestFile(temporary, payload))
	loaded, err = loadRemoteDeliveryCursor(stateDirectory, identity, "archive", fingerprint)
	require.NoError(t, err)
	require.Equal(t, second, loaded)
	require.NoFileExists(t, temporary)
}

func writeRemoteDeliveryTestFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return err
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
