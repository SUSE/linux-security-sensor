// +build linux

package bpf

import (
	_ "embed"

	libbpf "github.com/aquasecurity/libbpfgo"
        "www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/tcpsnoop.bpf.o
//go:embed tcpsnoop.bpf.o
var bpfCode []byte

const (
	OUT_CON  = 0
	IN_CON   = 1
	AF_INET  = 2
	AF_INET6 = 10
)

type TcpsnoopEvent struct {
	Saddr [16]byte
	Daddr [16]byte
	Task  [16]byte
	Af    uint32 // AF_INET or AF_INET6
	Pid   uint32
	Uid   uint32
	Rport uint16
	Lport uint16
	Dir   uint8
}

func initBpf() (*libbpf.Module, error) {
	bpfModule, err := bpf.LoadBpfModule("tcpsnoop", bpfCode)
	if err != nil {
		return nil, err
	}

	if err = bpf.AttachKretprobe(bpfModule, "inet_csk_accept_retprobe", "inet_csk_accept"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	if err = bpf.AttachKretprobe(bpfModule, "tcp_v4_connect_ret", "tcp_v4_connect"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	if err = bpf.AttachKprobe(bpfModule, "tcp_v4_connect", "tcp_v4_connect"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	return bpfModule, nil
}
