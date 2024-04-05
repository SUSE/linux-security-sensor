package utils

import (
	"sync/atomic"
)

type Refcount struct {
	count atomic.Int32
}

func NewRefcount() *Refcount {
	ref := &Refcount{}
	ref.count.Store(1)

	return ref
}

func (self *Refcount) Get() {
	for {
		current := self.count.Load()
		if self.count.Load() == 0 {
			panic("Bad refcount, can't Get() free object")
		}
		if self.count.CompareAndSwap(current, current + 1) {
			return
		}
	}
}

// Returns true if the last reference was dropped
func (self *Refcount) Put() bool {
	if self.count.Load() <= 0 {
		panic("Bad refcount, can't Put() free object")
	}
	if self.count.Add(-1) == 0 {
		return true
	}
	return false
}

func (self *Refcount) Reset() {
	self.count.Store(1)
}
