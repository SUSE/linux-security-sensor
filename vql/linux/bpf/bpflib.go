//go:build linux

package bpf

import (
	"fmt"
	"os"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	"www.velocidex.com/golang/velociraptor/logging"
)

const (
	enableDebug = false
)

func LoadBpfModule(name string, bpfCode []byte, globals map[string]any) (*libbpf.Module, error) {
	var bpfModule *libbpf.Module
	var err error

	moduleArgs := libbpf.NewModuleArgs{
		BPFObjBuff: bpfCode,
		BPFObjName: name,
	}

	if !helpers.OSBTFEnabled() {
		var ok bool
		moduleArgs.BTFObjPath, ok = os.LookupEnv("BTF_PATH")
		if !ok || moduleArgs.BTFObjPath == "" {
			return nil, fmt.Errorf("System doesn't have CONFIG_DEBUG_INFO_BTF and BTF_PATH env var not set")
		}

		_, err := os.Stat(moduleArgs.BTFObjPath)
		if err != nil {
			return nil, err
		}
	}

	if bpfModule, err = libbpf.NewModuleFromBufferArgs(moduleArgs); err != nil {
		return nil, err
	}

	for name, value := range globals {
		if err := bpfModule.InitGlobalVariable(name, value); err != nil {
			bpfModule.Close()
			return nil, err
		}
	}

	if err = bpfModule.BPFLoadObject(); err != nil {
		bpfModule.Close()
		return nil, err
	}

	return bpfModule, nil
}

func AttachKprobe(bpfModule *libbpf.Module, progName string, attachFunc string) error {
	bpfProg, err := bpfModule.GetProgram(progName)
	if err != nil {
		return err
	}

	_, err = bpfProg.AttachKprobe(attachFunc)
	if err != nil {
		return err
	}

	return nil
}

func AttachKretprobe(bpfModule *libbpf.Module, progName string, attachFunc string) error {
	bpfProg, err := bpfModule.GetProgram(progName)
	if err != nil {
		return err
	}

	_, err = bpfProg.AttachKretprobe(attachFunc)
	if err != nil {
		return err
	}

	return nil
}

func SetLoggerCallback(logger *logging.LogContext) {
	libbpf.SetLoggerCbs(libbpf.Callbacks{
		Log: func(level int, msg string) {
			switch level {
			case libbpf.LibbpfInfoLevel:
				logger.Info(msg)
			case libbpf.LibbpfWarnLevel:
				logger.Warn(msg)
			case libbpf.LibbpfDebugLevel:
				logger.Debug(msg)
			}
		},
		LogFilters: []func(level int, msg string) bool{
			func(level int, msg string) bool {
				return level == libbpf.LibbpfDebugLevel && !enableDebug
			},
		},
	})
}
