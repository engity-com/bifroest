package cast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	audit "github.com/engity-com/bifroest/pkg/audit/evidence"
	configuration "github.com/engity-com/bifroest/pkg/configuration/names"
	connection "github.com/engity-com/bifroest/pkg/connection/id"
	session "github.com/engity-com/bifroest/pkg/session/id"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/google/uuid"
)

// Do not let a new public ID formatter change the canonical bytes committed by
// an old native seal. Read wire IDs retain their original text for canonical
// verification; only newly constructed metadata uses the selected writer style.
type metadataJSON struct {
	Schema       string                 `json:"schema,omitempty"`
	RecordingID  string                 `json:"recordingId"`
	ConnectionID string                 `json:"connectionId"`
	SessionID    string                 `json:"sessionId"`
	OperationID  string                 `json:"operationId"`
	Flow         configuration.FlowName `json:"flow"`
	Task         audit.SessionTask      `json:"task"`
	Pty          bool                   `json:"pty"`
	ProducerID   audit.ProducerId       `json:"producerId"`
	StartedAt    time.Time              `json:"startedAt"`
	User         string                 `json:"user,omitempty"`
}

func (m CastMetadata) MarshalJSON() ([]byte, error) {
	return (castMetadataWire{CastMetadata: m}).MarshalJSON()
}
func (m *CastMetadata) UnmarshalJSON(data []byte) error {
	var value castMetadataWire
	if err := value.UnmarshalJSON(data); err != nil {
		return err
	}
	*m = value.CastMetadata
	return nil
}

func (w castMetadataWire) MarshalJSON() ([]byte, error) {
	format := uuidtext.Format
	if w.legacyUUIDs {
		format = uuidtext.Classic
	}
	ids := w.readIDs
	if ids[0] == "" {
		ids = [4]string{format(w.RecordingId), format(w.ConnectionId), format(w.SessionId), format(w.OperationId)}
	}
	return json.Marshal(metadataJSON{w.Schema, ids[0], ids[1], ids[2], ids[3], w.Flow, w.Task, w.Pty, w.ProducerId, w.StartedAt, w.User})
}
func (w *castMetadataWire) UnmarshalJSON(data []byte) error {
	var raw metadataJSON
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	texts := [4]string{raw.RecordingID, raw.ConnectionID, raw.SessionID, raw.OperationID}
	var ids [4][16]byte
	for index, text := range texts {
		value, err := uuidtext.Parse(text)
		if err != nil {
			return fmt.Errorf("invalid recording context UUID: %w", err)
		}
		ids[index] = value
	}
	metadata := CastMetadata{RecordingId: Id(ids[0]), ConnectionId: connection.Id(ids[1]), SessionId: session.Id(ids[2]), OperationId: uuid.UUID(ids[3]), Flow: raw.Flow, Task: raw.Task, Pty: raw.Pty, ProducerId: raw.ProducerID, StartedAt: raw.StartedAt, User: raw.User}
	*w = castMetadataWire{Schema: raw.Schema, CastMetadata: metadata, readIDs: texts}
	return nil
}
