//go:build linux

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/artifacts"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/velociraptor/utils"
	"www.velocidex.com/golang/velociraptor/vql"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/linux/bpf"
	"www.velocidex.com/golang/vfilter"
)

const (
	EXECSNOOP   = "execsnoop"
	RINGBUF_MAP = "rb_map"
)

type ExecsnoopPlugin struct{}

func (self ExecsnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name:     "execsnoop",
		Doc:      "Report execve system calls",
		Metadata: vql.VQLMetadata().Permissions(acls.MACHINE_STATE).Build(),
	}
}

func (self ExecsnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {

	outputCh := make(chan vfilter.Row)

	go func() {
		defer close(outputCh)
		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("execsnoop: %s", err)
			return
		}

		clientCfg, ok := artifacts.GetConfig(scope)
		if !ok {
			scope.Log("execsnoop: unable to get config")
			return
		}

		cfgObj := &config_proto.Config{Client: clientCfg}
		logger := logging.GetLogger(cfgObj, &logging.ClientComponent)

		subscriber := bpf.GetManager().Subscribe(EXECSNOOP, &publisher{logger: logger})
		defer bpf.GetManager().Unsubscribe(EXECSNOOP, subscriber)

		for {
			select {
			case <-ctx.Done():
				return

			case event := <-subscriber.EventCh:
				outputCh <- event

			case err := <-subscriber.ErrorCh:
				scope.Log("%v", err)
				return
			}
		}
	}()

	return outputCh
}

// event received from bpf
type bpfEvent struct {
	Pid     uint32
	Ppid    uint32
	Uid     uint32
	ExeLen  uint32
	ArgvLen uint32
	CwdLen  uint32
	// note: corresponding field for `u8 buf[BUF_MAX]` omitted
}

// event for sending to velociraptor
type Event struct {
	Time time.Time
	Pid  uint32
	Ppid uint32
	Uid  uint32
	Cwd  string
	Exe  string
	Argv string
}

// pathFromParts returns the path in the normal form. The ebpf program
// provides the path components in reverse order and \0 delimited.
// e.g. given prog\0dir2\0dir1\0\mnt\0 return /mnt/dir1/dir2/prog
func pathFromParts(s []byte) string {
	parts := bytes.Split(s, []byte{0x00})

	for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
		parts[left], parts[right] = parts[right], parts[left]
	}

	return string(bytes.Join(parts, []byte("/")))
}

func parseArgs(s []byte) string {
	s = bytes.TrimSuffix(s, []byte{0x00})
	s = bytes.ReplaceAll(s, []byte{0x00}, []byte(" "))
	return string(s)
}

func parseData(data []byte) (Event, error) {
	var event bpfEvent
	eventSize := uint32(unsafe.Sizeof(event))
	eventBuf := bytes.NewBuffer(data[:eventSize])
	err := binary.Read(eventBuf, utils.NativeEndian(), &event)
	if err != nil {
		return Event{}, err
	}

	// extract the variable length fields: argv, exe filename
	// and cwd that were passed by the bpf program in event->buf
	argvEnd := eventSize + event.ArgvLen
	argv := parseArgs(data[eventSize:argvEnd])

	exeEnd := argvEnd + event.ExeLen
	exe := pathFromParts(data[argvEnd:exeEnd])

	cwd := "/"
	if event.CwdLen > 0 {
		cwdEnd := exeEnd + event.CwdLen
		cwd = pathFromParts(data[exeEnd:cwdEnd])
	}

	return Event{
		Time: time.Now(),
		Pid:  event.Pid,
		Ppid: event.Ppid,
		Uid:  event.Uid,
		Cwd:  cwd,
		Exe:  exe,
		Argv: argv,
	}, nil
}

type publisher struct {
	wg     sync.WaitGroup
	cancel func()
	logger *logging.LogContext
}

func (p *publisher) Start() {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	bpfModuleLoadDoneCh := make(chan struct{})

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		bpfModule, err := initBpf(p.logger)
		bpfModuleLoadDoneCh <- struct{}{}
		if err != nil {
			e := fmt.Errorf("execsnoop: initBpf: %s", err)
			bpf.GetManager().PublishError(ctx, EXECSNOOP, e)
			return
		}
		defer bpfModule.Close()

		eventsCh := make(chan []byte)
		ringBuffer, err := bpfModule.InitRingBuf(RINGBUF_MAP, eventsCh)
		if err != nil {
			e := fmt.Errorf("execsnoop: InitRingBuf: %s", err)
			bpf.GetManager().PublishError(ctx, EXECSNOOP, e)
			return
		}
		ringBuffer.Poll(300)

		for {
			select {
			case <-ctx.Done():
				return

			case data, ok := <-eventsCh:
				if !ok {
					e := fmt.Errorf("execsnoop: events channel was closed")
					bpf.GetManager().PublishError(ctx, EXECSNOOP, e)
					return
				}
				event, err := parseData(data)
				if err != nil {
					p.logger.Warnf("execsnoop: failed to decode received data: %s", err)
					continue
				}
				bpf.GetManager().PublishEvent(ctx, EXECSNOOP, event)
			}
		}
	}()

	<-bpfModuleLoadDoneCh // wait until the BPF module is loaded
}

func (p *publisher) Stop() {
	p.cancel()
	p.wg.Wait()
}

func init() {
	vql_subsystem.RegisterPlugin(&ExecsnoopPlugin{})
}
