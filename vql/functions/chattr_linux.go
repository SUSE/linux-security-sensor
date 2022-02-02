package functions

import (
	"context"
	"os"
	"syscall"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

const FS_IOC_GETFLAGS uintptr = 0x80086601
const (
	// from /usr/include/linux/fs.h
	FS_SECRM_FL        = 0x00000001 /* Secure deletion */
	FS_UNRM_FL         = 0x00000002 /* Undelete */
	FS_COMPR_FL        = 0x00000004 /* Compress file */
	FS_SYNC_FL         = 0x00000008 /* Synchronous updates */
	FS_IMMUTABLE_FL    = 0x00000010 /* Immutable file */
	FS_APPEND_FL       = 0x00000020 /* writes to file may only append */
	FS_NODUMP_FL       = 0x00000040 /* do not dump file */
	FS_NOATIME_FL      = 0x00000080 /* do not update atime */
	FS_DIRTY_FL        = 0x00000100
	FS_COMPRBLK_FL     = 0x00000200 /* One or more compressed clusters */
	FS_NOCOMP_FL       = 0x00000400 /* Don't compress */
	FS_ENCRYPT_FL      = 0x00000800 /* Compression error */
	FS_BTREE_FL        = 0x00001000 /* btree format dir */
	FS_INDEX_FL        = 0x00001000 /* hash-indexed directory */
	FS_IMAGIC_FL       = 0x00002000 /* AFS directory */
	FS_JOURNAL_DATA_FL = 0x00004000 /* Reserved for ext3 */
	FS_NOTAIL_FL       = 0x00008000 /* file tail should not be merged */
	FS_DIRSYNC_FL      = 0x00010000 /* dirsync behaviour (directories only) */
	FS_TOPDIR_FL       = 0x00020000 /* Top of directory hierarchies*/
	FS_HUGE_FILE_FL    = 0x00040000 /* Extents */
	FS_EXTENT_FL       = 0x00080000 /* Extents */
	FS_DIRECTIO_FL     = 0x00100000 /* Use direct i/o */
	FS_EA_INODE_FL     = 0x00200000 /* Reserved for ext4 */
	FS_EOFBLOCKS_FL    = 0x00400000 /* Reserved for ext4 */
	FS_NOCOW_FL        = 0x00800000 /* Do not cow file */
	FS_INLINE_DATA_FL  = 0x10000000 /* Do not cow file */
	FS_PROJINHERIT_FL  = 0x20000000 /* Create with parents projid */
	FS_CASEFOLD_FL     = 0x40000000 /* Create with parents projid */
	FS_RESERVED_FL     = 0x80000000 /* reserved for ext2 lib */
)

func ioctl(f *os.File, request uintptr, attrp *int32) error {

	argp := uintptr(unsafe.Pointer(attrp))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, argp)

	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}

func getattrs(f *os.File) (int32, error) {
	attr := int32(-1)
	err := ioctl(f, FS_IOC_GETFLAGS, &attr)
	return attr, err
}

type ChattrArgs struct {
	Path string `vfilter:"required,field=file,doc=The file whose attributes we require"`
}

type ChattrFunction struct{}

type Chattr int32

func (self Chattr) String() string {

	var buf [19]byte
	flags := map[uint32]byte{
		FS_SECRM_FL:        's',
		FS_UNRM_FL:         'u',
		FS_SYNC_FL:         'S',
		FS_DIRSYNC_FL:      'D',
		FS_IMMUTABLE_FL:    'i',
		FS_APPEND_FL:       'a',
		FS_NODUMP_FL:       'd',
		FS_NOATIME_FL:      'A',
		FS_COMPR_FL:        'c',
		FS_ENCRYPT_FL:      'E',
		FS_JOURNAL_DATA_FL: 'j',
		FS_INDEX_FL:        'I',
		FS_NOTAIL_FL:       't',
		FS_TOPDIR_FL:       'T',
		FS_EXTENT_FL:       'e',
		FS_NOCOW_FL:        'C',
		FS_INLINE_DATA_FL:  'N',
		FS_PROJINHERIT_FL:  'P',
		FS_NOCOMP_FL:       'm',
	}
	i := 0

	for k, v := range flags {
		if (uint32(self) & k) == k {
			buf[i] = v
		} else {
			buf[i] = '-'
		}
		i++
	}

	return string(buf[:])
}

func (self ChattrFunction) Call(ctx context.Context,
	scope vfilter.Scope,
	args *ordereddict.Dict) vfilter.Any {
	arg := &ChattrArgs{}
	err := arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
	if err != nil {
		scope.Log("chattr: %s", err.Error())
		return false
	}

	file, err := os.Open(arg.Path)
	if err != nil {
		scope.Log("chattr(%s): %s", arg.Path, err.Error())
		return false
	}
	defer file.Close()

	lsattr, err := getattrs(file)
	if err != nil {
		scope.Log("chattr(%s): %s", arg.Path, err.Error())
		return false
	}

	return Chattr(lsattr)
}

func (self ChattrFunction) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.FunctionInfo {
	return &vfilter.FunctionInfo{
		Name:    "chattr",
		Doc:     "Queries the attributes for a file.",
		ArgType: type_map.AddType(scope, &ChattrArgs{}),
	}
}

func init() {
	vql_subsystem.RegisterFunction(&ChattrFunction{})
}
