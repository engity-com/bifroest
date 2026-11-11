package evidence

import "github.com/engity-com/bifroest/pkg/uuidtext"

// NormalizeEventIDs is used only when creating new records/projections, never
// while reconstructing canonical bytes of historical signed JSON records.
func NormalizeEventIDs(event Event) (Event, error) {
	for _, value := range []*string{&event.ConnectionId, &event.SessionId, &event.OperationId, &event.RecordingId} {
		if *value != "" {
			text, err := uuidtext.Normalize(*value)
			if err != nil {
				return Event{}, err
			}
			*value = text
		}
	}
	return event, nil
}
