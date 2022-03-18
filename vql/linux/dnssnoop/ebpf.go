// +build linux,linuxbpf

package linux

import (
	_ "embed"
	"fmt"
	"golang.org/x/sys/unix"
	"os"

	bpf "www.velocidex.com/golang/velociraptor/third_party/libbpfgo"
	"www.velocidex.com/golang/velociraptor/third_party/libbpfgo/helpers"
)

//go:embed dnssnoop.bpf.o
var bpfCode []byte

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func initSocket(bpfFd int) (int, error) {

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("Error creating raw socket: %s\n", err.Error())
	}

	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, bpfFd)
	if err != nil {
		return -1, fmt.Errorf("Error attaching bpf prog to socket: %s\n", err.Error())
	}

	return fd, nil
}

func initBpf() (*bpf.Module, int, error) {
	var bpfModule *bpf.Module
	var err error

	moduleArgs := bpf.NewModuleArgs{
		BPFObjBuff: bpfCode,
		BPFObjName: "dnssnoop",
	}

	if !helpers.OSBTFEnabled() {
		var ok bool
		moduleArgs.BTFObjPath, ok = os.LookupEnv("BTF_PATH")
		if !ok || moduleArgs.BTFObjPath == "" {
			return nil, -1, fmt.Errorf("System doesn't have CONFIG_DEBUG_INFO_BTF and BTF_PATH env var not set")
		}

		_, err = os.Stat(moduleArgs.BTFObjPath)
		if err != nil {
			return nil, -1, err
		}
	}

	if bpfModule, err = bpf.NewModuleFromBufferArgs(moduleArgs); err != nil {
		bpfModule.Close()
		return nil, -1, err
	}

	if err = bpfModule.BPFLoadObject(); err != nil {
		bpfModule.Close()
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
