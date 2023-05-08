// +build !windows

package functions

import (
	"golang.org/x/sys/unix"
)

var (
	cacheSize int64 = 1000
)

type unixHashResultCacheEntry struct {
	result	HashResult
	stat	unix.Stat_t
}

func (self *unixHashResultCacheEntry) Size() int {
	return 1
}

func (self *unixHashResultCacheEntry) Validate(filename string) (bool, error) {
	stat := unix.Stat_t{}
	err := unix.Stat(filename, &stat)

	if err != nil {
		return false, err
	}

	// If the file was replaced, it will probably have a different inode
	// number (but we can't depend on that).
	// If the mtime was modified afterward, the ctime will change.
	// If it was overwritten, the mtime will change.
	return self.stat.Dev == stat.Dev &&
	       self.stat.Ino == stat.Ino &&
	       self.stat.Mtim == stat.Mtim &&
	       self.stat.Ctim == stat.Ctim, nil
}

func (self *unixHashResultCacheEntry) Result() *HashResult {
	return &self.result
}

func newHashResultCacheEntry(filename string) (*unixHashResultCacheEntry, error) {
	stat := unix.Stat_t{}
	err := unix.Stat(filename, &stat)

	if err != nil {
		return nil, err
	}

	return &unixHashResultCacheEntry{ stat: stat, }, nil
}
