package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestJournalRecordV1Golden(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	id := uuid.MustParse("34e34ab8-7457-4d88-a5e4-c57791775c3a")
	recordedAt := time.Date(2026, time.September, 13, 12, 34, 56, 123456789, time.UTC)

	record, payload, hash, err := newJournalRecord(identity, journalHash{}, Event{
		Name:         EventNameSessionTaskCompleted,
		Domain:       EventDomainSession,
		Outcome:      EventOutcomeSuccess,
		Flow:         "production",
		ConnectionId: id.String(),
		SessionId:    "82d8fdda-4730-43b7-bfde-72733c217bde",
		OperationId:  "6d05798f-b877-4191-8aa0-4576a30411ad",
		SessionTask:  SessionTaskExec,
	}, id, recordedAt)
	require.NoError(t, err)

	require.Equal(t, `{"schema":"bifroest.audit-record/v1","id":"34e34ab8-7457-4d88-a5e4-c57791775c3a","recordedAt":"2026-09-13T12:34:56.123456789Z","producerId":"95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298","event":{"name":"session.task.completed","domain":"session","outcome":"success","flow":"production","connectionId":"34e34ab8-7457-4d88-a5e4-c57791775c3a","sessionId":"82d8fdda-4730-43b7-bfde-72733c217bde","operationId":"6d05798f-b877-4191-8aa0-4576a30411ad","sessionTask":"exec"},"previousHash":"0000000000000000000000000000000000000000000000000000000000000000","publicKey":"AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4","signature":"FWQ+xHzQ4Lt2CaFJ6xk/87BiEe9U4MrSU2IdTXjeEowPS8zUAHoBu0QBvW2+Cp/60utleNfbM02/5JdOwVFWBQ=="}`, string(payload))
	require.Equal(t, "95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298", record.ProducerId.String())
	require.Equal(t, "15643ec47cd0e0bb7609a149eb193ff3b06211ef54e0cad253621d4d78de128c0f4bccd4007a01bb4401bd6dbe0a9ffad2eb6578d7db334dbfe4974ec1515605", hex.EncodeToString(record.Signature))
	require.Equal(t, "99bed71d199f0fc38ad716dc5c6b84c5a14da1fd3dbf134fd3b0c8ed8103991e", hash.String())
}
