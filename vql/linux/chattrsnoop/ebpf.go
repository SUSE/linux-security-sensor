//go:build linux && linuxbpf
// +build linux,linuxbpf

package linux

import (
	_ "embed"

	bpf "github.com/aquasecurity/libbpfgo"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpflib"
)

//go:embed chattrsnoop.bpf.o
var bpfCode []byte

func initBpf() (*bpf.Module, error) {
	bpfModule, err := bpflib.LoadBpfModule("chattrsnoop", bpfCode)
	if err != nil {
		return nil, err
	}

	if err = bpflib.AttachKprobe(bpfModule, "trace_vfs_ioctl", "do_vfs_ioctl"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	return bpfModule, nil
}
