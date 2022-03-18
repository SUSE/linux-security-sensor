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

#define PACKET_HOST 0
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
	u16 sport;
	u64 offset = 0;
	u16 protocol;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &protocol, 2) < 0)
		return 0;

	offset = sizeof(struct ethhdr);

	switch (bpf_ntohs(protocol)) {
		case ETH_P_IP:
			protocol = 0;
			if (bpf_skb_load_bytes(skb, offset + offsetof(struct iphdr, protocol), &protocol, 1) < 0)
				return 0;

			offset += sizeof(struct iphdr);

			break;
		case ETH_P_IPV6:
			protocol = 0;
			if (bpf_skb_load_bytes(skb, offset + offsetof(struct ipv6hdr, nexthdr), &protocol, 1) < 0)
				return 0;

			offset += sizeof(struct ipv6hdr);

			break;
		default:
			return 0;
	}

	if (protocol != IPPROTO_UDP)
		return 0;

	if (bpf_skb_load_bytes(skb, offset + offsetof(struct udphdr, source), &sport, 2) < 0)
		return 0;

	if (bpf_ntohs(sport) != 53)
		return 0;

	return skb->len;
}

char LICENSE[] SEC("license") = "GPL";
