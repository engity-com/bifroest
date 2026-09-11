package common

import (
	"sync"
	"sync/atomic"

	"github.com/engity-com/bifroest/pkg/errors"
)

type KeyedMutex[K comparable] struct {
	keyToMutex map[K]*keyMutex[K]
	uberMutex  sync.RWMutex
	init       sync.Once
}

type Unlocker func()

func (this *KeyedMutex[K]) Lock(key K) Unlocker {
	instance := this.acquire(key)
	instance.mutex.Lock()
	return instance.unlock
}

func (this *KeyedMutex[K]) RLock(key K) Unlocker {
	instance := this.acquire(key)
	instance.mutex.RLock()
	return instance.rUnlock
}

func (this *KeyedMutex[K]) acquire(key K) *keyMutex[K] {
	this.init.Do(func() {
		this.keyToMutex = make(map[K]*keyMutex[K])
	})
	this.uberMutex.RLock()
	instance, ok := this.keyToMutex[key]
	if ok {
		instance.numberOfHoldes.Add(1)
		this.uberMutex.RUnlock()
		return instance
	}
	this.uberMutex.RUnlock()

	this.uberMutex.Lock()
	defer this.uberMutex.Unlock()

	instance, ok = this.keyToMutex[key]
	if !ok {
		instance = &keyMutex[K]{
			key:    key,
			parent: this,
		}
		this.keyToMutex[key] = instance
	}
	instance.numberOfHoldes.Add(1)
	return instance
}

type keyMutex[K comparable] struct {
	key            K
	parent         *KeyedMutex[K]
	mutex          sync.RWMutex
	numberOfHoldes atomic.Int32
}

func (this *keyMutex[K]) unlock() {
	this.mutex.Unlock()
	this.afterUnlock()
}

func (this *keyMutex[K]) rUnlock() {
	this.mutex.RUnlock()
	this.afterUnlock()
}

func (this *keyMutex[K]) afterUnlock() {
	left := this.numberOfHoldes.Add(-1)
	if left < 0 {
		panic(errors.System.Newf("possible mutex leak detected: number of active holder after unlock now at a negative value: %d", left))
	}
	if left > 0 {
		return
	}
	this.parent.uberMutex.Lock()
	defer this.parent.uberMutex.Unlock()
	if this.numberOfHoldes.Load() == 0 && this.parent.keyToMutex[this.key] == this {
		delete(this.parent.keyToMutex, this.key)
	}
}
