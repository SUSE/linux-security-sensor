//go:build linux

package bpf

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"syscall"

	libbpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/dnssnoop.bpf.o
//go:embed dnssnoop.bpf.o
var bpfCode []byte

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return utils.NativeEndian().Uint16(b)
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

func initBpf(logger *logging.LogContext) (*libbpf.Module, int, error) {
	bpf.SetLoggerCallback(logger)

	bpfModule, err := bpf.LoadBpfModule("dnssnoop", bpfCode, nil)
	if err != nil {
		return nil, -1, err
	}

	prog, _ := bpfModule.GetProgram("socket_filter")
	if prog == nil {
		bpfModule.Close()
		return nil, -1, fmt.Errorf("Couldn't find dnssnoop bpf program")
	}

	fd, err := initSocket(prog.FileDescriptor())
	if err != nil {
		bpfModule.Close()
		return nil, -1, err
	}

	return bpfModule, fd, nil
}
