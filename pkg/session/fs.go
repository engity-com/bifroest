package session

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	FsFileSession             = "s"
	FsFileLastAccessed        = "la"
	FsFileAccessToken         = "at"
	FsFileEnvironmentToken    = "et"
	FsFilePublicKeysPrefix    = "pk-"
	FsFilePublicKeysPrefixLen = len(FsFilePublicKeysPrefix)
)

type fs struct {
	repository *FsRepository

	flow configuration.FlowName
	id   Id

	info fsInfo
}

func (this *fs) init(repository *FsRepository, flow configuration.FlowName, id Id) {
	this.repository = repository
	this.flow = flow
	this.id = id
	this.info.init(this)
}

func (this *fs) GetField(name string, ce contextEnabled) (any, bool, error) {
	return this.info.GetField(name, ce)
}

func (this *fs) Info(context.Context) (Info, error) {
	return &this.info, nil
}

func (this *fs) Flow() configuration.FlowName {
	return this.flow
}

func (this *fs) Id() Id {
	return this.id
}

func (this *fs) String() string {
	return this.flow.String() + "/" + this.id.String()
}

func (this *fs) AuthorizationToken(ctx context.Context) ([]byte, error) {
	return this.getToken(ctx, FsFileAccessToken, "access")
}

func (this *fs) EnvironmentToken(ctx context.Context) ([]byte, error) {
	return this.getToken(ctx, FsFileEnvironmentToken, "environment")
}

func (this *fs) getToken(_ context.Context, kind, name string) (_ []byte, rErr error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()

	f, fn, err := this.repository.openRead(this.flow, this.id, kind)
	if sys.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer common.KeepCloseError(&rErr, f)

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read session's %s token file (%q) of %v: %w", name, fn, this, err)
	}
	return data, nil
}

func (this *fs) SetAuthorizationToken(ctx context.Context, data []byte) (rErr error) {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	return this.setAuthorizationToken(ctx, data)
}

func (this *fs) setAuthorizationToken(ctx context.Context, data []byte) (rErr error) {
	return this.setToken(ctx, data, FsFileAccessToken, "access")
}

func (this *fs) setEnvironmentToken(ctx context.Context, data []byte) (rErr error) {
	return this.setToken(ctx, data, FsFileEnvironmentToken, "environment")
}

func (this *fs) SetEnvironmentToken(ctx context.Context, data []byte) (rErr error) {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	return this.setEnvironmentToken(ctx, data)
}

func (this *fs) setToken(_ context.Context, data []byte, kind, name string) (rErr error) {
	if len(data) == 0 {
		fn, err := this.repository.file(this.flow, this.id, kind)
		if err != nil {
			return fmt.Errorf("cannot delete session's %stoken file (%q) of %v: %w", name, fn, this, err)
		}
		if err := os.Remove(fn); err != nil && !sys.IsNotExist(err) {
			return fmt.Errorf("cannot delete session's %s token file (%q) of %v: %w", name, fn, this, err)
		}
		return nil
	}

	f, fn, err := this.repository.openWrite(this.flow, this.id, kind, false)
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("cannot write session's %s token file (%q) of %v: %w", name, fn, this, err)
	}
	return nil
}

func (this *fs) HasPublicKey(ctx context.Context, pub ssh.PublicKey) (bool, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()

	return this.repository.hasPublicKey(ctx, this.flow, this.id, pub)
}

func (this *fs) AddPublicKey(ctx context.Context, pub ssh.PublicKey) error {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	return this.repository.addPublicKey(ctx, this.flow, this.id, pub)
}

func (this *fs) DeletePublicKey(ctx context.Context, pub ssh.PublicKey) error {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	return this.repository.deletePublicKey(ctx, this.flow, this.id, pub)
}

func (this *fs) NotifyLastAccess(_ context.Context, remote net.Remote, newState State) (State, error) {
	return this.notifyLastAccess(remote, newState)
}

func (this *fs) notifyLastAccess(remote net.Remote, newState State) (State, error) {
	var buf fsLastAccessed
	buf.at = time.Now().Truncate(time.Millisecond)
	buf.VRemoteUser = remote.User()
	buf.VRemoteHost = remote.Host()
	buf.init(&this.info)
	if err := buf.save(); err != nil {
		return 0, err
	}
	oldState := this.info.VState
	if newState != 0 && newState != this.info.VState {
		this.info.VState = newState
		if err := this.info.save(); err != nil {
			return 0, err
		}
	}
	return oldState, nil
}

func (this *fs) Dispose(ctx context.Context) (bool, error) {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	return this.repository.disposeBy(ctx, this.flow, this.id)
}
