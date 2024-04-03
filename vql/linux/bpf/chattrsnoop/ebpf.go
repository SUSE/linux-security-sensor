//go:build linux

package bpf

/*
#include <linux/fs.h>
*/
import "C"

import (
	_ "embed"

	libbpf "github.com/aquasecurity/libbpfgo"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/chattrsnoop.bpf.o
//go:embed chattrsnoop.bpf.o
var bpfCode []byte

func initBpf(logger *logging.LogContext) (*libbpf.Module, error) {
	bpf.SetLoggerCallback(logger)

	var globals = map[string]any{
		"FS_IOC_SETFLAGS": uint32(C.FS_IOC_SETFLAGS),
	}
	bpfModule, err := bpf.LoadBpfModule("chattrsnoop", bpfCode, globals)
	if err != nil {
		return nil, err
	}

	if err = bpf.AttachKprobe(bpfModule, "trace_security_file_ioctl", "security_file_ioctl"); err != nil {
		bpfModule.Close()
		return nil, err
	}

	return bpfModule, nil
}
