// +build linux

package bpf

import (
	_ "embed"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	libbpf "github.com/aquasecurity/libbpfgo"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/dnssnoop.bpf.o
//go:embed dnssnoop.bpf.o
var bpfCode []byte

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func initSocket(bpfFd int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("Error creating raw socket: %s\n", err.Error())
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, bpfFd)
	if err != nil {
		return -1, fmt.Errorf("Error attaching bpf prog to socket: %s\n", err.Error())
	}

	return fd, nil
}

func initBpf() (*libbpf.Module, int, error) {
	bpfModule, err := bpf.LoadBpfModule("dnssnoop", bpfCode)
	if err != nil {
		return nil, -1, err
	}

	prog, _ := bpfModule.GetProgram("socket_filter")
	if prog == nil {
		bpfModule.Close()
		return nil, -1, fmt.Errorf("Couldn't find dnssnoop bpf program")
	}

	fd, err := initSocket(prog.GetFd())
	if err != nil {
		bpfModule.Close()
		return nil, -1, err
	}

	return bpfModule, fd, nil
}
