//go:build linux && linuxbpf
// +build linux,linuxbpf

package linux

import (
	_ "embed"

	bpf "www.velocidex.com/golang/velociraptor/third_party/libbpfgo"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpflib"
)

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
	Ts_us uint64
	Af    uint32 // AF_INET or AF_INET6
	Pid   uint32
	Uid   uint32
	Rport uint16
	Lport uint16
	Dir   uint8
}

func initBpf() (*bpf.Module, error) {
	bpfModule, err := bpflib.LoadBpfModule("tcpsnoop", bpfCode)
	if err != nil {
		return nil, err
	}

	if err = bpflib.AttachKretprobe(bpfModule, "inet_csk_accept_retprobe", "inet_csk_accept"); err != nil {
		return nil, err
	}

	if err = bpflib.AttachKretprobe(bpfModule, "tcp_v4_connect_ret", "tcp_v4_connect"); err != nil {
		return nil, err
	}

	if err = bpflib.AttachKprobe(bpfModule, "tcp_v4_connect", "tcp_v4_connect"); err != nil {
		return nil, err
	}

	return bpfModule, nil
}
