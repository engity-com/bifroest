package service

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

type sessionConnectionKey struct {
	flow configuration.FlowName
	id   session.Id
}

type sessionConnectionEntry struct {
	connections map[managedConnection]struct{}
	revoked     bool
	created     time.Time
}

// Internal registrations use pointer implementations so connection identity is
// distinct from an ID supplied by a transport. Close must cancel pending I/O.
type managedConnection interface {
	bconn.LifetimeAware
	io.Closer
	IsClosed() bool
}

type sessionConnectionRegistry struct {
	runtime         *runtimeGenerations
	mutex           sync.Mutex
	sessions        map[sessionConnectionKey]*sessionConnectionEntry
	connections     map[managedConnection]sessionConnectionKey
	terminalsClosed bool
	observeAges     bool
	created         map[managedConnection]time.Time
}

func (this *sessionConnectionRegistry) monitoringAges(now time.Time) map[configuration.FlowName][2]monitoringAges {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	result := make(map[configuration.FlowName][2]monitoringAges)
	seen := make(map[sessionConnectionKey]bool)
	for conn, key := range this.connections {
		if conn.IsClosed() {
			continue
		}
		ages := result[key.flow]
		ages[1].add(this.created[conn], now)
		if !seen[key] {
			ages[0].add(this.sessions[key].created, now)
			seen[key] = true
		}
		result[key.flow] = ages
	}
	return result
}

// monitoringCounts inspects only the bounded in-memory registry, never sessions
// on disk or targets. Revocation tombstones and closed connections are excluded.
func (this *sessionConnectionRegistry) monitoringCounts() map[configuration.FlowName][2]int {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	result := make(map[configuration.FlowName][2]int)
	seen := make(map[sessionConnectionKey]struct{})
	for conn, key := range this.connections {
		if conn.IsClosed() {
			continue
		}
		counts := result[key.flow]
		counts[1]++
		if _, exists := seen[key]; !exists {
			counts[0]++
			seen[key] = struct{}{}
		}
		result[key.flow] = counts
	}
	return result
}

func (this *sessionConnectionRegistry) isRevoked(sess session.Session) bool {
	if sess == nil {
		return false
	}
	if this.runtime != nil && this.runtime.sessionRevoked(sess) {
		return true
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	entry := this.sessions[sessionConnectionKey{sess.Flow(), sess.Id()}]
	return entry != nil && entry.revoked
}

func (this *sessionConnectionRegistry) track(conn managedConnection, sess session.Session) {
	if isNilDependency(conn) || sess == nil {
		return
	}
	if !reflect.TypeOf(conn).Comparable() {
		_ = conn.Close()
		return
	}
	if this.runtime != nil && !this.runtime.bindConnection(conn, sess) {
		_ = conn.Close()
		return
	}
	key := sessionConnectionKey{sess.Flow(), sess.Id()}
	var created time.Time
	if this.observeAges {
		// Repository access happens on registration, never while collecting.
		if info, err := sess.Info(context.Background()); err == nil && info != nil {
			if value, err := info.Created(context.Background()); err == nil && value != nil {
				created = value.At()
			}
		}
	}
	this.mutex.Lock()
	if _, terminal := conn.(*terminalConnection); terminal && this.terminalsClosed {
		this.mutex.Unlock()
		_ = conn.Close()
		return
	}
	if conn.IsClosed() {
		this.mutex.Unlock()
		return
	}
	if old, ok := this.connections[conn]; ok && old != key {
		this.remove(conn, old)
	}
	entry := this.sessions[key]
	if entry == nil {
		entry = &sessionConnectionEntry{connections: make(map[managedConnection]struct{})}
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
	if entry.created.IsZero() {
		entry.created = created
	}
	if this.observeAges {
		if this.created == nil {
			this.created = make(map[managedConnection]time.Time)
		}
		if _, exists := this.created[conn]; !exists {
			at := time.Now()
			if ssh, ok := conn.(*connection); ok {
				at = ssh.createdAt
			}
			this.created[conn] = at
		}
	}
	entry.connections[conn] = struct{}{}
	if this.connections == nil {
		this.connections = make(map[managedConnection]sessionConnectionKey)
	}
	this.connections[conn] = key
	this.mutex.Unlock()
}

func (this *sessionConnectionRegistry) untrack(conn managedConnection) {
	if isNilDependency(conn) || !reflect.TypeOf(conn).Comparable() {
		return
	}
	if this.runtime != nil {
		this.runtime.untrack(conn)
	}
	this.mutex.Lock()
	if key, ok := this.connections[conn]; ok {
		this.remove(conn, key)
	}
	this.mutex.Unlock()
}

// remove must be called with mutex held. Revoked entries remain until final deletion.
func (this *sessionConnectionRegistry) remove(conn managedConnection, key sessionConnectionKey) {
	delete(this.connections, conn)
	delete(this.created, conn)
	entry := this.sessions[key]
	delete(entry.connections, conn)
	if !entry.revoked && len(entry.connections) == 0 {
		delete(this.sessions, key)
	}
}

// finalSessionDeleted removes the revocation tombstone only after a durable
// session deletion. Never call this on disposal or an attempted deletion:
// late registrations must still be rejected while the session exists.
func (this *sessionConnectionRegistry) finalSessionDeleted(flow configuration.FlowName, id session.Id) {
	if this.runtime != nil {
		this.runtime.finalSessionDeleted(flow, id)
	}
	key := sessionConnectionKey{flow: flow, id: id}
	this.mutex.Lock()
	if entry := this.sessions[key]; entry != nil && entry.revoked && len(entry.connections) == 0 {
		delete(this.sessions, key)
	}
	this.mutex.Unlock()
}

func (this *sessionConnectionRegistry) revoke(flow configuration.FlowName, id session.Id) error {
	if this.runtime != nil {
		connections := this.runtime.revokeSession(flow, id)
		var persistErr error
		if persistence := this.runtime.persistence; persistence != nil {
			persistErr = persistence.revoker.RevokeRuntimeSession(context.Background(), flow, id)
			if persistErr != nil {
				this.runtime.stop()
				persistence.failed(persistErr)
			}
		}
		return errors.Join(persistErr, closeSessionConnections(connections))
	}
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
	connections := make([]managedConnection, 0, len(entry.connections))
	for conn := range entry.connections {
		connections = append(connections, conn)
		delete(this.connections, conn)
		delete(this.created, conn)
	}
	entry.connections = nil
	this.mutex.Unlock()

	return closeSessionConnections(connections)
}

// disconnect takes a snapshot without revoking the session. Connections tracked
// after this snapshot are new connections and are intentionally left alone.
func (this *sessionConnectionRegistry) disconnect(flow configuration.FlowName, id session.Id) error {
	if this.runtime != nil {
		return closeSessionConnections(this.runtime.snapshotSessionConnections(flow, id))
	}
	this.mutex.Lock()
	var connections []managedConnection
	if entry := this.sessions[sessionConnectionKey{flow, id}]; entry != nil {
		for conn := range entry.connections {
			connections = append(connections, conn)
		}
	}
	this.mutex.Unlock()
	return closeSessionConnections(connections)
}

func closeSessionConnections(connections []managedConnection) error {
	// A blocked interceptor cleanup must not delay closing other SSH sockets.
	var closing sync.WaitGroup
	failures := make([]error, len(connections))
	for index, conn := range connections {
		closing.Add(1)
		go func() {
			defer closing.Done()
			failures[index] = conn.Close()
		}()
	}
	closing.Wait()
	return errors.Join(failures...)
}

// HTTP hijacks/future framed transports are not owned by the SSH server's grace
// mechanism. Stop their connections explicitly and let the common driver drain.
func (this *sessionConnectionRegistry) closeTerminals() error {
	if this.runtime != nil {
		return closeSessionConnections(this.runtime.closeTerminals())
	}
	this.mutex.Lock()
	this.terminalsClosed = true
	var closing []managedConnection
	for conn := range this.connections {
		if _, ok := conn.(*terminalConnection); ok {
			closing = append(closing, conn)
		}
	}
	this.mutex.Unlock()
	return closeSessionConnections(closing)
}
