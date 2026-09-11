package audit

// Event is the domain payload accepted by a Recorder. The recorder adds common
// metadata and the journal adds its persistence envelope.
type Event struct {
	Name string `json:"name"`
}
