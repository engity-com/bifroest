package service

import (
	"sync"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

type sessionConnectionKey struct {
	flow configuration.FlowName
	id   session.Id
}

type sessionConnectionEntry struct {
	connections map[*connection]struct{}
	revoked     bool
}

type sessionConnectionRegistry struct {
	mutex       sync.Mutex
	sessions    map[sessionConnectionKey]*sessionConnectionEntry
	connections map[*connection]sessionConnectionKey
}

func (this *sessionConnectionRegistry) track(conn *connection, sess session.Session) {
	if conn == nil || sess == nil {
		return
	}
	key := sessionConnectionKey{sess.Flow(), sess.Id()}
	this.mutex.Lock()
	if conn.closed.Load() {
		this.mutex.Unlock()
		return
	}
	if old, ok := this.connections[conn]; ok && old != key {
		this.remove(conn, old)
	}
	entry := this.sessions[key]
	if entry == nil {
		entry = &sessionConnectionEntry{connections: make(map[*connection]struct{})}
		if this.sessions == nil {
			this.sessions = make(map[sessionConnectionKey]*sessionConnectionEntry)
		}
		this.sessions[key] = entry
	}
	if entry.revoked {
		this.mutex.Unlock()
		_ = conn.Close()
		return
	}
	entry.connections[conn] = struct{}{}
	if this.connections == nil {
		this.connections = make(map[*connection]sessionConnectionKey)
	}
	this.connections[conn] = key
	this.mutex.Unlock()
}

func (this *sessionConnectionRegistry) untrack(conn *connection) {
	this.mutex.Lock()
	if key, ok := this.connections[conn]; ok {
		this.remove(conn, key)
	}
	this.mutex.Unlock()
}

// remove must be called with mutex held. Revoked entries remain to reject late registrations.
func (this *sessionConnectionRegistry) remove(conn *connection, key sessionConnectionKey) {
	delete(this.connections, conn)
	entry := this.sessions[key]
	delete(entry.connections, conn)
	if !entry.revoked && len(entry.connections) == 0 {
		delete(this.sessions, key)
	}
}

func (this *sessionConnectionRegistry) revoke(flow configuration.FlowName, id session.Id) {
	key := sessionConnectionKey{flow, id}
	this.mutex.Lock()
	entry := this.sessions[key]
	if entry == nil {
		entry = &sessionConnectionEntry{}
		if this.sessions == nil {
			this.sessions = make(map[sessionConnectionKey]*sessionConnectionEntry)
		}
		this.sessions[key] = entry
	}
	entry.revoked = true
	connections := make([]*connection, 0, len(entry.connections))
	for conn := range entry.connections {
		connections = append(connections, conn)
		delete(this.connections, conn)
	}
	entry.connections = nil
	this.mutex.Unlock()

	// A blocked interceptor cleanup must not delay closing other SSH sockets.
	var closing sync.WaitGroup
	for _, conn := range connections {
		closing.Add(1)
		go func() {
			defer closing.Done()
			_ = conn.Close()
		}()
	}
	closing.Wait()
}
