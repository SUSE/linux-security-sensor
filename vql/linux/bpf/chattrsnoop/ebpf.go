// +build linux

package bpf

import (
	_ "embed"

	libbpf "github.com/aquasecurity/libbpfgo"
        "www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/chattrsnoop.bpf.o
//go:embed chattrsnoop.bpf.o
var bpfCode []byte

func initBpf() (*libbpf.Module, error) {
	bpfModule, err := bpf.LoadBpfModule("chattrsnoop", bpfCode)
	if err != nil {
		return nil, err
	}

	if err = bpf.AttachKprobe(bpfModule, "trace_vfs_ioctl", "do_vfs_ioctl"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	return bpfModule, nil
}
