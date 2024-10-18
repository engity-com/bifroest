package wel

import log "github.com/echocat/slf4g"

type coreLoggerRenamed struct {
	*coreLogger
	name string
}

// Log implements log.CoreLogger#Log(event).
func (instance *coreLoggerRenamed) Log(event log.Event, skipFrames uint16) {
	instance.log(instance.name, event, skipFrames+1)
}

// GetName implements log.CoreLogger#GetName().
func (instance *coreLoggerRenamed) GetName() string {
	return instance.name
}
