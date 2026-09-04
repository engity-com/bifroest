package service

import (
	"io"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectionWriteDeadlineRefreshesReadIdleDeadline(t *testing.T) {
	now := time.Now()
	underlying := &deadlineRecordingConn{}
	conn := &connection{Conn: underlying}

	firstDeadline := now.Add(time.Hour)
	_, err := conn.applyEffectiveConnectionDeadlines("write", firstDeadline, connectionValidityResultConnectionIdle)
	require.NoError(t, err)
	firstReadDeadline, _ := underlying.deadlines()
	secondDeadline := firstDeadline.Add(time.Minute)
	_, err = conn.applyEffectiveConnectionDeadlines("write", secondDeadline, connectionValidityResultConnectionIdle)
	require.NoError(t, err)
	secondReadDeadline, _ := underlying.deadlines()

	require.Equal(t, firstDeadline, firstReadDeadline)
	require.Equal(t, secondDeadline, secondReadDeadline)
}

func TestConnectionActivityPreservesEarlierLibraryDeadline(t *testing.T) {
	now := time.Now()
	underlying := &deadlineRecordingConn{}
	conn := &connection{Conn: underlying}
	libraryReadDeadline := now.Add(time.Minute)
	require.NoError(t, conn.SetReadDeadline(libraryReadDeadline))

	_, err := conn.applyEffectiveConnectionDeadlines("write", now.Add(time.Hour), connectionValidityResultConnectionIdle)
	require.NoError(t, err)
	readDeadline, writeDeadline := underlying.deadlines()

	require.Equal(t, libraryReadDeadline, readDeadline)
	require.True(t, writeDeadline.After(libraryReadDeadline))
}

type deadlineRecordingConn struct {
	mutex         sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (this *deadlineRecordingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (this *deadlineRecordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (this *deadlineRecordingConn) Close() error           { return nil }
func (this *deadlineRecordingConn) LocalAddr() gonet.Addr  { return nil }
func (this *deadlineRecordingConn) RemoteAddr() gonet.Addr { return nil }
func (this *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.readDeadline = deadline
	this.writeDeadline = deadline
	return nil
}
func (this *deadlineRecordingConn) SetReadDeadline(deadline time.Time) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.readDeadline = deadline
	return nil
}
func (this *deadlineRecordingConn) SetWriteDeadline(deadline time.Time) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.writeDeadline = deadline
	return nil
}
func (this *deadlineRecordingConn) deadlines() (time.Time, time.Time) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.readDeadline, this.writeDeadline
}
