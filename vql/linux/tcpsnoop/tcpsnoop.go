//go:build linux
// +build linux

package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
)

type TcpsnoopPlugin struct{}

func (self TcpsnoopPlugin) Info(scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "tcpsnoop",
		Doc:  "Snoop incoming/outgoin tcp connection",
	}
}

type Event struct {
	Saddr string `json:"saddr"`
	Daddr string `json:"daddr"`
	Task  string `json:"task"`
	Af    string `json:"protocol"` // AF_INET or AF_INET6
	Pid   uint32 `json:"pid"`
	Uid   uint32 `json:"uid"`
	Rport uint16 `json:"rport"`
	Lport uint16 `json:"lport"`
	Dir   string `json:"con_dir"`
}

func (self TcpsnoopPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)
	bpf, err := initBpf()

	if err != nil {
		scope.Log("tcpsnoop: %s", err)
		bpf.Close()
		return output_chan
	}

	go func() {
		defer bpf.Close()

		err := vql_subsystem.CheckAccess(scope, acls.MACHINE_STATE)
		if err != nil {
			scope.Log("tcpsnoop: %s", err)
			return
		}

		// Load bpf program and attach to tracepoints
		initBpf()

		eventsChan := make(chan []byte)
		lostChan := make(chan uint64)

		perfBuffer, err := bpf.InitPerfBuf("events", eventsChan, lostChan, 128)
		if err != nil {
			scope.Log("tcpsnoop: %s", err)
		}

		perfBuffer.Start()

		for data := range eventsChan {
			var event TcpsnoopEvent

			var event2 Event
			// Parses raw event from the ebpf map
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)

			// Now we make into a more userfriendly struct for sending to VRR
			event2.Lport = event.Lport
			event2.Rport = event.Rport
			event2.Uid = event.Uid
			event2.Pid = event.Pid
			event2.Task = string(bytes.Trim(event.Task[:], "\000"))

			if event.Af == AF_INET {
				event2.Af = "IPv4"
				event2.Saddr = net.IP.String(event.Saddr[:4])
				event2.Daddr = net.IP.String(event.Daddr[:4])
			} else {
				event2.Saddr = net.IP.String(event.Saddr[:])
				event2.Daddr = net.IP.String(event.Daddr[:])
				event2.Af = "IPv6"
			}

			if event.Dir == OUT_CON {
				event2.Dir = "OUTGOING"
				event2.Saddr, event2.Daddr = event2.Daddr, event2.Saddr
			} else {
				event2.Dir = "INCOMING"
			}

			if err != nil {
				scope.Log("failed to decode received data: %s\n", err)
				continue
			}

			// print the tcp event to VRR's channel
			output_chan <- event2
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&TcpsnoopPlugin{})
}
