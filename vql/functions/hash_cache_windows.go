package functions

import (
	"errors"
)

type uncachedHashResultEntry struct{}

var (
	cacheSize         int64 = 0
	errNotImplemented       = errors.New("Hash caching is not implemented for Windows")
)

func (self *uncachedHashResultEntry) Size() int {
	return 1
}

func (self *uncachedHashResultEntry) Validate(filename string) (bool, error) {
	return false, errNotImplemented
}

func (self *uncachedHashResultEntry) Result() *HashResult {
	return nil
}

func newHashResultCacheEntry(filename string) (*uncachedHashResultEntry, error) {
	return nil, errNotImplemented
}
