// +build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 SUSE Linux Products GmbH. All Rights Reserved.
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define FS_IOC_SETFLAGS 0x40086602

#define S_IMMUTABLE (1<<3)
#define MAX_PERCPU_BUFSIZE (1<<15)
#define PATH_MAX 4096
#define MAX_PATH_COMPONENTS 20
#define FS_IMMUTABLE_FL                 0x00000010
#define IDX(x) ((x) & ((MAX_PERCPU_BUFSIZE>>1)-1))

struct buf_t {
	u8 buf[MAX_PERCPU_BUFSIZE];
};

static const char slash = '/';
static const int zero = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct buf_t);
} buf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
}
events SEC(".maps");

static __always_inline int
process_dentry(struct buf_t *string_p, int buf_off, struct dentry *dentry)
{
	// Add this dentry name to path
	struct qstr d_name = BPF_CORE_READ(dentry, d_name);
	unsigned int len = (d_name.len + 1) & (PATH_MAX - 1);
	unsigned int off = buf_off - len;

	// Is string buffer big enough for dentry name?
	int sz = 0;
	if (off <= buf_off)	// verify no wrap occurred
		sz = bpf_probe_read_kernel_str(&(string_p->buf[IDX(off)]), len,
					       (void *)d_name.name);
	else
		return -1;

	if (sz > 1) {
		buf_off -= 1;	// remove null byte termination with slash sign
		bpf_probe_read_kernel(&(string_p->buf[IDX(buf_off)]), 1, &slash);
		buf_off -= sz - 1;
	} else {
		// If sz is 0 or 1 we have an error (path can't be null nor an empty string)
		return -1;
	}

	return buf_off;
}

static __always_inline u32
get_path_str(struct path *path, struct buf_t *string_p)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
	struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
	struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
	struct mount *mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);

	int buf_off = (MAX_PERCPU_BUFSIZE >> 1);

#pragma unroll
	for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
		struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);

		if (dentry == mnt_root || dentry == d_parent) {
			if (dentry != mnt_root) {
				// We reached root, but not mount root - escaped?
				break;
			}
			if (mnt_p != mnt_parent_p) {
				// We reached root, but not global root - continue with mount point path
				dentry = BPF_CORE_READ(mnt_p, mnt_mountpoint);
				mnt_p = BPF_CORE_READ(mnt_p, mnt_parent);
				mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);
				vfsmnt = &mnt_p->mnt;
				mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
				continue;
			}
			// Global root - path fully parsed
			break;
		}

		int ret = process_dentry(string_p, buf_off, dentry);
		if (ret < 0)
			break;

		buf_off = ret;
		dentry = d_parent;
	}

	// Add leading slash
	buf_off -= 1;
	bpf_probe_read_kernel(&(string_p->buf[IDX(buf_off)]), 1, &slash);
	// Null terminate the path string, this replaces the final / with a null
	// char
	bpf_probe_read_kernel(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1,
		       &zero);

	return buf_off;
}

SEC("kprobe/do_vfs_ioctl")
int BPF_KPROBE(trace_vfs_ioctl, struct file *filp, unsigned int fd,
	       unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	struct inode *inode = BPF_CORE_READ(filp, f_inode);

	if (cmd != FS_IOC_SETFLAGS)
		return 0;

	if (bpf_core_field_exists(((struct inode_operations *)0)->fileattr_set)) {
		if (!BPF_CORE_READ(inode, i_op, fileattr_set))
			return 0;
	} else {
		if (!BPF_CORE_READ(filp, f_op, unlocked_ioctl))
			return 0;
	}

	if (bpf_probe_read_user(&flags, sizeof(unsigned long), (void *)arg) < 0)
		return 0;

	bool is_immutable = BPF_CORE_READ(inode, i_flags) & S_IMMUTABLE;

	if (!(!!(flags & FS_IMMUTABLE_FL) ^ is_immutable))
		return 0;

	struct buf_t *buf = bpf_map_lookup_elem(&buf_map, &zero);
	if (buf == NULL)
		return 0;

	struct path *p = __builtin_preserve_access_index(&filp->f_path);

	u32 offset = get_path_str(p, buf);
	// Add set/clear indicator
	offset -= 1;
	if (is_immutable && !(flags & FS_IMMUTABLE_FL))
		buf->buf[IDX(offset)] = 0;
	else if (flags & FS_IMMUTABLE_FL)
		buf->buf[IDX(offset)] = 1;

	u32 str_len = IDX((MAX_PERCPU_BUFSIZE >> 1) - offset);

	return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
				     &buf->buf[IDX(offset)], str_len);
}

char LICENSE[] SEC("license") = "GPL";
