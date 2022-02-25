// +build linux,linuxbpf

package linux

import (
	_ "embed"
	"errors"
	"os"

	bpf "www.velocidex.com/golang/velociraptor/third_party/libbpfgo"
	"www.velocidex.com/golang/velociraptor/third_party/libbpfgo/helpers"
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

func attachKprobe(bpfModule *bpf.Module, progName string, attachFunc string) error {
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

func attachKretprobe(bpfModule *bpf.Module, progName string, attachFunc string) error {
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

func initBpf() (*bpf.Module, error) {
	var bpfModule *bpf.Module
	var err error

	moduleArgs := bpf.NewModuleArgs{
		BPFObjBuff: bpfCode,
		BPFObjName: "tcpsnoop",
	}

	if !helpers.OSBTFEnabled() {
		var ok bool
		moduleArgs.BTFObjPath, ok = os.LookupEnv("TCPSNOOP_BTF")
		if !ok || moduleArgs.BTFObjPath == "" {
			return nil, errors.New("System doesn't have CONFIG_DEBUG_INFO_BTF and TCPSNOOP_BTF env var not set")
		}

		_, err = os.Stat(moduleArgs.BTFObjPath)
		if err != nil {
			return nil, err
		}
	}

	if bpfModule, err = bpf.NewModuleFromBufferArgs(moduleArgs); err != nil {
		return nil, err
	}

	if err = bpfModule.BPFLoadObject(); err != nil {
		return nil, err
	}

	if err = attachKretprobe(bpfModule, "inet_csk_accept_retprobe", "inet_csk_accept"); err != nil {
		return nil, err
	}

	if err = attachKretprobe(bpfModule, "tcp_v4_connect_ret", "tcp_v4_connect"); err != nil {
		return nil, err
	}

	if err = attachKprobe(bpfModule, "tcp_v4_connect", "tcp_v4_connect"); err != nil {
		return nil, err
	}

	return bpfModule, nil
}
