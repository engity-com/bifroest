package session

import (
	"bytes"
	"net"
	"strings"
	"time"
)

func (this *fsSession) At() time.Time {
	return this.VCreatedAt
}

func (this *fsSession) RemoteUser() string {
	return strings.Clone(this.VRemoteUser)
}

func (this *fsSession) RemoteAddr() net.IP {
	return bytes.Clone(this.VRemoteAddr)
}
