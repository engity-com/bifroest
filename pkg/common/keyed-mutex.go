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
	return this.lockBy(key, func(instance *keyMutex[K]) Unlocker {
		instance.numberOfHoldes.Add(1)
		instance.mutex.Lock()
		return instance.unlock
	})
}

func (this *KeyedMutex[K]) RLock(key K) Unlocker {
	return this.lockBy(key, func(instance *keyMutex[K]) Unlocker {
		instance.numberOfHoldes.Add(1)
		instance.mutex.RLock()
		return instance.rUnlock
	})
}

func (this *KeyedMutex[K]) lockBy(key K, instanceLocker func(*keyMutex[K]) Unlocker) Unlocker {
	this.init.Do(func() {
		this.keyToMutex = make(map[K]*keyMutex[K])
	})
	rLockActive := true
	this.uberMutex.RLock()
	uberRUnlock := func() {
		if rLockActive {
			this.uberMutex.RUnlock()
		}
		rLockActive = false
	}
	defer uberRUnlock()

	instance, ok := this.keyToMutex[key]
	if ok {
		uberRUnlock()
		return instanceLocker(instance)
	}
	uberRUnlock()

	this.uberMutex.Lock()
	defer this.uberMutex.Unlock()

	instance, ok = this.keyToMutex[key]
	if ok {
		return instanceLocker(instance)
	}

	instance = &keyMutex[K]{
		key:    key,
		parent: this,
	}
	this.keyToMutex[key] = instance

	return instanceLocker(instance)
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

	delete(this.parent.keyToMutex, this.key)
}
