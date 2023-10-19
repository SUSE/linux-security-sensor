// +build linux

package bpf

import (
	"fmt"
	"os"

	libbpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
)

func LoadBpfModule(name string, bpfCode []byte) (*libbpf.Module, error) {
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
