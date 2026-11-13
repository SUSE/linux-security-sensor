// +build ignore

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 SUSE Linux Products GmbH. All Rights Reserved.
//
// Based on tcpaccept(8) from BCC by Brendan Gregg
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

#define OUT_CONNECTION 0
#define IN_CONNECTION 1

struct event {
	union {
		__u32 raddr_v4;
		__u8 raddr_v6[16];
	};
	union {
		__u32 laddr_v4;
		__u8 laddr_v6[16];
	};
	char task[TASK_COMM_LEN];
	__u32 af;		// AF_INET or AF_INET6
	__u32 pid;
	__u32 uid;
	__u16 rport;
	__u16 lport;
	__u8 direction;
};

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
}
events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	struct sock **skpp;
	struct sock *sk;
	__u16 rport, lport;
	struct event event = { };

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	lport = BPF_CORE_READ(sk, __sk_common.skc_num);

	rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.rport = rport;
	event.lport = lport;
	event.direction = OUT_CONNECTION;
	bpf_get_current_comm(event.task, sizeof(event.task));

	if (ip_ver == 4) {
		event.af = AF_INET;
		BPF_CORE_READ_INTO(&event.laddr_v4, sk,
				   __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event.raddr_v4, sk, __sk_common.skc_daddr);
	} else if (ip_ver == 6
		   && bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		event.af = AF_INET6;
		BPF_CORE_READ_INTO(&event.laddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.
				   u6_addr32);
		BPF_CORE_READ_INTO(&event.raddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

static __always_inline int bpf__inet_csk_accept(struct pt_regs *ctx, int ret)
{
	struct sock *sk;
	u16 protocol;
	__u16 rport, lport, family;
	struct event event = { };
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	sk = (struct sock *)PT_REGS_RC(ctx);
	if (!sk)
		return 0;

	lport = BPF_CORE_READ(sk, __sk_common.skc_num);

	rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);

	if (protocol != IPPROTO_TCP)
		return 0;

	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.rport = rport;
	event.lport = lport;
	event.direction = IN_CONNECTION;
	bpf_get_current_comm(event.task, sizeof(event.task));

	if (family == AF_INET) {
		event.af = AF_INET;
		BPF_CORE_READ_INTO(&event.laddr_v4, sk,
				   __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event.raddr_v4, sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6
		   && bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) {
		event.af = AF_INET6;
		BPF_CORE_READ_INTO(&event.laddr_v6, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.
				   u6_addr32);
		BPF_CORE_READ_INTO(&event.raddr_v6, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_retprobe, int ret)
{
	return bpf__inet_csk_accept(ctx, ret);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret, 6);
}

char LICENSE[] SEC("license") = "GPL";
