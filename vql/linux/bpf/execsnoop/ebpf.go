//go:build linux

package bpf

import (
	_ "embed"

	libbpf "github.com/aquasecurity/libbpfgo"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
)

//go:generate make -C .. ${PWD}/execsnoop.bpf.o
//go:embed execsnoop.bpf.o
var bpfCode []byte

func initBpf(logger *logging.LogContext) (*libbpf.Module, error) {
	bpf.SetLoggerCallback(logger)

	bpfModule, err := bpf.LoadBpfModule("execsnoop", bpfCode, nil)
	if err != nil {
		return nil, err
	}

	prog, err := bpfModule.GetProgram("tracepoint__sched__sched_process_exec")
	if err != nil {
		return nil, err
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_exec")
	if err != nil {
		return nil, err
	}

	return bpfModule, nil
}
