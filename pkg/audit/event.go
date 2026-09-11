package audit

// Event is the domain payload accepted by a Recorder. Its common metadata and
// integrity envelope will be added with the durable journal implementation.
type Event struct {
	Name string
}
