/*
   Velociraptor - Dig Deeper
   Copyright (C) 2019-2022 Rapid7 Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package functions

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/accessors"
	"www.velocidex.com/golang/velociraptor/accessors/file"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
	"www.velocidex.com/golang/velociraptor/third_party/cache"
)

var (
	pool = sync.Pool{
		New: func() interface{} {
			buffer := make([]byte, 64*1024) // 64kb chunks
			return &buffer
		},
	}
)

type HashResult struct {
	MD5    string
	md5    hash.Hash
	SHA1   string
	sha1   hash.Hash
	SHA256 string
	sha256 hash.Hash
}

type HashResultCacheEntry interface {
	cache.Value
	Validate(filename string) (bool, error)
	Result() *HashResult
}

type HashResultCache struct {
	scope		vfilter.Scope
	lru_cache	*cache.LRUCache
}

func (self *HashResultCache) Get(filename string) (HashResultCacheEntry, bool) {
	if cacheSize > 0 {
		res, ok := self.lru_cache.Get(filename)
		if ok {
			return res.(HashResultCacheEntry), ok
		}
	}

	return nil, false
}

func (self *HashResultCache) Set(filename string, entry HashResultCacheEntry) {
	if cacheSize > 0 {
		self.lru_cache.Set(filename, entry)
	}
}

func (self *HashResultCache) Delete(filename string) {
	if cacheSize > 0 {
		_ = self.lru_cache.Delete(filename)
	}
}

var mu sync.Mutex

func GetHashResultCache(scope vfilter.Scope) *HashResultCache {
	if cacheSize <= 0 {
		return nil
	}

	defer mu.Unlock()
	mu.Lock()
	key := "hash_result_cache"
	root_scope := vql_subsystem.GetRootScope(scope)

	cache_ctx, ok := vql_subsystem.CacheGet(root_scope, key).(*HashResultCache)
	if !ok {
		cache_ctx = &HashResultCache{
			lru_cache: cache.NewLRUCache(cacheSize),
			scope: scope,
		}
		root_scope.AddDestructor(func() { cache_ctx.lru_cache.Clear() })
		vql_subsystem.CacheSet(root_scope, key, cache_ctx)
	}

	return cache_ctx
}

func (self *HashResult) ToDict() *ordereddict.Dict {
	return ordereddict.NewDict().
		Set("MD5", self.MD5).
		Set("SHA1", self.SHA1).
		Set("SHA256", self.SHA256)
}

type HashFunctionArgs struct {
	Path       *accessors.OSPath `vfilter:"required,field=path,doc=Path to open and hash."`
	Accessor   string            `vfilter:"optional,field=accessor,doc=The accessor to use"`
	HashSelect []string          `vfilter:"optional,field=hashselect,doc=The hash function to use (MD5,SHA1,SHA256)"`
}

// HashFunction calculates a hash of a file. It may be expensive
// so we make it cancelllable.
type HashFunction struct{}

func (self *HashFunction) Call(ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) vfilter.Any {
	var cache *HashResultCache

	arg := &HashFunctionArgs{}
	err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
	if err != nil {
		scope.Log("hash: %v", err)
		return vfilter.Null{}
	}

	cached_buffer := pool.Get().(*[]byte)
	defer pool.Put(cached_buffer)

	buf := *cached_buffer

	err = vql_subsystem.CheckFilesystemAccess(scope, arg.Accessor)
	if err != nil {
		scope.Log("hash: %s", err)
		return vfilter.Null{}
	}

	fs, err := accessors.GetAccessor(arg.Accessor, scope)
	if err != nil {
		scope.Log("hash: %v", err)
		return vfilter.Null{}
	}

	result := &HashResult{}

	// What has the call requested
	var wantMD5, wantSHA1, wantSHA256 bool

	// What do we need to generate (i.e. what is uncached?)
	var needMD5, needSHA1, needSHA256 bool

	if arg.HashSelect == nil {
		wantMD5 = true
		wantSHA1 = true
		wantSHA256 = true
		needMD5 = true
		needSHA1 = true
		needSHA256 = true
	} else {
		for _, hash_opt := range arg.HashSelect {
			switch hash_opt {
			case "sha256", "SHA256":
				wantSHA256 = true
				needSHA256 = true
			case "sha1", "SHA1":
				wantSHA1 = true
				needSHA1 = true
			case "md5", "MD5":
				wantMD5 = true
				needMD5 = true
			default:
				scope.Log("hashselect option %s not recognized (should be md5, sha1, sha256)",
					hash_opt)
				return vfilter.Null{}
			}
		}
	}

	var entry HashResultCacheEntry
	path := arg.Path.String()
	_, useCache := fs.(*file.OSFileSystemAccessor)
	if useCache {
		cache = GetHashResultCache(scope)

		entry, isCached := cache.Get(path)
		if isCached {
			isValid, _ := entry.Validate(path)
			if isValid {
				cachedResult := entry.Result()
				if wantMD5 && cachedResult.MD5 != "" {
					result.MD5 = cachedResult.MD5
					needMD5 = false
				}
				if wantSHA1 && cachedResult.SHA1 != "" {
					result.SHA1 = cachedResult.SHA1
					needSHA1 = false
				}
				if wantSHA256 && cachedResult.SHA256 != "" {
					result.SHA256 = cachedResult.SHA256
					needSHA256 = false
				}

			}  else {
				cache.Delete(path)
				entry = nil
			}
		}
	}


	if needMD5 || needSHA1 || needSHA256 {
		file, err := fs.OpenWithOSPath(arg.Path)
		if err != nil {
			scope.Log("hash: %s: %v", path, err)
			return vfilter.Null{}
		}
		defer file.Close()

		if needMD5 {
			result.md5 = md5.New()
		}

		if needSHA1 {
			result.sha1 = sha1.New()
		}

		if needSHA256 {
			result.sha256 = sha256.New()
		}

		Done:
		for {
			select {
			case <-ctx.Done():
				return vfilter.Null{}

			default:
				n, err := file.Read(buf)

				// We are done!
				if n == 0 || err == io.EOF {
					if n == 0 {
						break Done
					}
				} else if err != nil {
					scope.Log("hash: %v", err)
					return vfilter.Null{}
				}

				if needMD5 {
					_, _ = result.md5.Write(buf[:n])
				}

				if needSHA1 {
					_, _ = result.sha1.Write(buf[:n])
				}

				if needSHA256 {
					_, _ = result.sha256.Write(buf[:n])
				}

				// Charge an op for each buffer we read
				scope.ChargeOp()
			}
		}

		if needMD5 {
			result.MD5 = fmt.Sprintf("%x", result.md5.Sum(nil))
		}

		if needSHA1 {
			result.SHA1 = fmt.Sprintf("%x", result.sha1.Sum(nil))
		}

		if needSHA256 {
			result.SHA256 = fmt.Sprintf("%x", result.sha256.Sum(nil))
		}

		if useCache {
			if entry == nil {
				entry, err = newHashResultCacheEntry(path)
			}

			if entry != nil {
				cachedResult := entry.Result()
				if needMD5 {
					cachedResult.MD5 = result.MD5
				}
				if needSHA1 {
					cachedResult.SHA1 = result.SHA1
				}
				if needSHA256 {
					cachedResult.SHA256 = result.SHA256
				}

				cache.Set(path, entry)
			}
		}
	}

	return result.ToDict()
}

func (self HashFunction) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.FunctionInfo {
	return &vfilter.FunctionInfo{
		Name:    "hash",
		Doc:     "Calculate the hash of a file.",
		ArgType: type_map.AddType(scope, &HashFunctionArgs{}),
		Version: 2,
	}
}

func init() {
	vql_subsystem.RegisterFunction(&HashFunction{})
}
