package session

func (this *fs) HasActiveConnections() bool {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()
	if byID := this.repository.connectionInterceptors[this.flow]; byID != nil {
		if stack := byID[this.id]; stack != nil {
			return stack.active.Load() > 0
		}
	}
	return false
}
